#define _GNU_SOURCE
/* Port of erts/emulator/beam/erl_bif_re.c:199-205, 527-550, OTP-29.1.1. */
#include "local_config.h"
#include "pcre2.h"
#include "pcre2_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Port of erts/emulator/beam/erl_bif_re.c:159-203 (stack_guard), OTP-29.1.1. */
static int ar_re_stack_guard(uint32_t depth, void *unused) {
    char marker;
    (void)depth;
    (void)unused;
#if defined(__APPLE__)
    char *high = (char *)pthread_get_stackaddr_np(pthread_self());
    size_t size = pthread_get_stacksize_np(pthread_self());
    return (uintptr_t)&marker < (uintptr_t)(high - size + 10 * 1024);
#elif defined(__linux__)
    pthread_attr_t attr;
    void *base;
    size_t size;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return depth > 1000;
    if (pthread_attr_getstack(&attr, &base, &size) != 0) {
        pthread_attr_destroy(&attr);
        return depth > 1000;
    }
    pthread_attr_destroy(&attr);
    return (uintptr_t)&marker < (uintptr_t)((char *)base + 10 * 1024);
#else
    return depth > 1000;
#endif
}

static pcre2_compile_context *ar_re_tmp_compile_ctx;
static pthread_once_t ar_re_compile_ctx_once = PTHREAD_ONCE_INIT;

static void ar_re_init_compile_context(void) {
    ar_re_tmp_compile_ctx = pcre2_compile_context_create(NULL);
    if (ar_re_tmp_compile_ctx)
        pcre2_set_compile_recursion_guard(ar_re_tmp_compile_ctx, ar_re_stack_guard, NULL);
}

pcre2_code *ar_re_compile(const uint8_t *pattern, size_t len, uint32_t options,
                          uint32_t newline, uint32_t bsr, int *error, size_t *offset) {
    pthread_once(&ar_re_compile_ctx_once, ar_re_init_compile_context);
    if (!ar_re_tmp_compile_ctx) return NULL;
    pcre2_compile_context *ctx = ar_re_tmp_compile_ctx;
    if (newline || bsr) {
        ctx = pcre2_compile_context_copy(ar_re_tmp_compile_ctx);
        if (!ctx) return NULL;
        if (newline) pcre2_set_newline(ctx, newline);
        if (bsr) pcre2_set_bsr(ctx, bsr);
    }
    pcre2_code *code = pcre2_compile(pattern, len, options, error, offset, ctx);
    if (ctx != ar_re_tmp_compile_ctx) pcre2_compile_context_free(ctx);
    return code;
}

void ar_re_code_free(pcre2_code *code) { pcre2_code_free(code); }
int ar_re_info_u32(const pcre2_code *code, uint32_t what, uint32_t *out) {
    return pcre2_pattern_info(code, what, out);
}
int ar_re_info_ptr(const pcre2_code *code, uint32_t what, const uint8_t **out) {
    return pcre2_pattern_info(code, what, out);
}
int ar_re_error_message(int code, uint8_t *out, size_t cap) {
    return pcre2_get_error_message(code, out, cap);
}
int ar_re_version(uint8_t *out) { return pcre2_config(PCRE2_CONFIG_VERSION, out); }
int ar_re_serialize(const pcre2_code *code, uint8_t **out, size_t *len) {
    return pcre2_serialize_encode(&code, 1, out, len, NULL);
}
void ar_re_serial_free(uint8_t *p) { pcre2_serialize_free(p); }
int ar_re_deserialize(const uint8_t *bytes, size_t len, pcre2_code **code) {
    const size_t prefix = sizeof(pcre2_serialized_data) + TABLES_LENGTH;
    const size_t block_offset = offsetof(pcre2_real_code, blocksize);
    CODE_BLOCKSIZE_TYPE blocksize;
    if (len < prefix || len - prefix < block_offset + sizeof(blocksize))
        return PCRE2_ERROR_BADSERIALIZEDDATA;
    memcpy(&blocksize, bytes + prefix + block_offset, sizeof(blocksize));
    if (blocksize <= sizeof(pcre2_real_code) || blocksize > len - prefix)
        return PCRE2_ERROR_BADSERIALIZEDDATA;
    return pcre2_serialize_decode(code, 1, bytes, NULL);
}
int ar_re_capture_name(const pcre2_code *code, const uint8_t *name) {
    return pcre2_substring_number_from_name(code, name);
}
int ar_re_capture_name_range(const pcre2_code *code, const uint8_t *name,
                             const uint8_t **first, const uint8_t **last) {
    return pcre2_substring_nametable_scan(code, name, first, last);
}

typedef struct {
    int rc;
    uint64_t loops_consumed;
} ar_re_match_result;

/* Port of erts/emulator/beam/erl_bif_re.c:1685-1795 (re_run) and :1841-1900 (re_exec_trap),
 * OTP-29.1.1. One call runs at most `loop_budget` loops. When the budget runs out the match
 * state (`*session`, erts' RestartContext) stays allocated and the caller resumes it with the
 * next call; mode 1 frees an unfinished session. The code and subject must stay alive and
 * unmoved while a session exists. */
typedef struct {
    pcre2_match_data *data;
    pcre2_match_context *ctx;
    void *restart;
} ar_re_session;

ar_re_match_result ar_re_match(const pcre2_code *code, const uint8_t *subject,
                              size_t len, size_t offset, uint32_t options,
                              int match_limit, int depth_limit,
                              size_t *ovector, uint32_t ovec_count,
                              int loop_budget, ar_re_session *session, int mode) {
    ar_re_match_result result = {0, 0};
    if (mode == 1) {
        if (session) {
            if (session->restart) pcre2_free_restart_data(session->data);
            if (session->ctx) pcre2_match_context_free(session->ctx);
            pcre2_match_data_free(session->data);
            memset(session, 0, sizeof(*session));
        }
        return result;
    }
    int rc;
    if (!session->data) {
        session->data = pcre2_match_data_create(ovec_count, NULL);
        if (!session->data) { result.rc = PCRE2_ERROR_NOMEMORY; return result; }
        if (match_limit >= 0 || depth_limit >= 0) {
            session->ctx = pcre2_match_context_create(NULL);
            if (!session->ctx) {
                pcre2_match_data_free(session->data);
                memset(session, 0, sizeof(*session));
                result.rc = PCRE2_ERROR_NOMEMORY;
                return result;
            }
            if (match_limit >= 0) pcre2_set_match_limit(session->ctx, (uint32_t)match_limit);
            if (depth_limit >= 0) pcre2_set_depth_limit(session->ctx, (uint32_t)depth_limit);
        }
        pcre2_set_restart_data(session->data, &session->restart);
        pcre2_set_restart_flags(session->data, 0);
        pcre2_set_loops_left(session->data, loop_budget);
        rc = pcre2_match(code, subject, len, offset, options, session->data, session->ctx);
    } else {
        pcre2_set_loops_left(session->data, loop_budget);
        pcre2_set_restart_flags(session->data, 0);
        rc = pcre2_match(NULL, NULL, 0, 0, 0, session->data, NULL);
    }
    result.loops_consumed = (uint64_t)(loop_budget - pcre2_get_loops_left(session->data));
    result.rc = rc;
    if (rc == PCRE2_ERROR_LOOP_LIMIT) {
        return result;
    }
    if (rc > 0) {
        size_t *src = pcre2_get_ovector_pointer(session->data);
        for (int i = 0; i < rc && (uint32_t)i < ovec_count; i++) {
            ovector[2*i] = src[2*i];
            ovector[2*i+1] = src[2*i+1];
        }
    }
    if (session->restart) pcre2_free_restart_data(session->data);
    if (session->ctx) pcre2_match_context_free(session->ctx);
    pcre2_match_data_free(session->data);
    memset(session, 0, sizeof(*session));
    return result;
}
