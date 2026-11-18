// Test-only oracle: encodes cases with the asmjit that erts 29.1.1 vendors, configured as erts
// configures it (beam_jit_common.cpp: code.init(Environment::host()), no base address,
// EncodingOptions kOptimizeForSize | kOptimizedAlign). Never linked into Arinsal.
//
// stdin: one case per line, statements separated by ';'. Statement forms:
//   <mnemonic> [operand {, operand}]   operands: register, integer, [size ptr] [memory], label
//   bind <label>                       label names are arbitrary identifiers (L1, done, ...)
//   align <n>                          Assembler::align(AlignMode::kCode, n)
// A label used but never bound is bound at the end of the case.
// stdout: one line per case: "OK <hex bytes>" or "ERR <asmjit error name>".
#include <asmjit/core.h>
#include <asmjit/x86.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace asmjit;

namespace {

std::string trim(const std::string &s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::vector<std::string> split(const std::string &s, char sep) {
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char c : s) {
        if (c == '[') depth++;
        if (c == ']') depth--;
        if (c == sep && depth == 0) {
            out.push_back(trim(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(trim(cur));
    return out;
}

struct Case {
    x86::Assembler *a;
    std::map<std::string, Label> labels;

    Label label(const std::string &name) {
        auto it = labels.find(name);
        if (it != labels.end()) return it->second;
        Label l = a->new_label();
        labels.emplace(name, l);
        return l;
    }
};

bool parse_reg(const std::string &n, x86::Gp *gp, x86::Vec *vec, int *vec_bits) {
    static const char *q[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    static const char *d[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    static const char *w[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    static const char *bl[] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
    static const char *bh[] = {"ah", "ch", "dh", "bh"};
    for (int i = 0; i < 8; i++) {
        if (n == q[i]) return *gp = x86::gpq(i), true;
        if (n == d[i]) return *gp = x86::gpd(i), true;
        if (n == w[i]) return *gp = x86::gpw(i), true;
        if (n == bl[i]) return *gp = x86::gpb_lo(i), true;
    }
    for (int i = 0; i < 4; i++)
        if (n == bh[i]) return *gp = x86::gpb_hi(i), true;
    if (n.size() >= 2 && n[0] == 'r' && isdigit((unsigned char)n[1])) {
        char *end;
        long id = strtol(n.c_str() + 1, &end, 10);
        std::string suf = end;
        if (id >= 8 && id <= 15) {
            if (suf.empty()) return *gp = x86::gpq(id), true;
            if (suf == "d") return *gp = x86::gpd(id), true;
            if (suf == "w") return *gp = x86::gpw(id), true;
            if (suf == "b") return *gp = x86::gpb_lo(id), true;
        }
    }
    for (const char *pre : {"xmm", "ymm"}) {
        if (n.compare(0, 3, pre) == 0 && n.size() > 3 && isdigit((unsigned char)n[3])) {
            long id = strtol(n.c_str() + 3, nullptr, 10);
            *vec = pre[0] == 'x' ? x86::xmm(id) : x86::ymm(id);
            *vec_bits = pre[0] == 'x' ? 128 : 256;
            return true;
        }
    }
    return false;
}

bool is_number(const std::string &s) {
    if (s.empty()) return false;
    size_t i = (s[0] == '-' || s[0] == '+') ? 1 : 0;
    return i < s.size() && isdigit((unsigned char)s[i]);
}

int64_t parse_number(const std::string &s) {
    // Values above INT64_MAX (0xffff_ffff_ffff_ffff) wrap as two's complement.
    bool neg = !s.empty() && s[0] == '-';
    std::string t = (neg || s[0] == '+') ? s.substr(1) : s;
    uint64_t v = strtoull(t.c_str(), nullptr, 0);
    return (int64_t)(neg ? (0 - v) : v);
}

uint32_t size_of(const std::string &kw) {
    if (kw == "byte") return 1;
    if (kw == "word") return 2;
    if (kw == "dword") return 4;
    if (kw == "qword") return 8;
    if (kw == "xmmword") return 16;
    if (kw == "ymmword") return 32;
    return 0;
}

// Parses `[size ptr] [base + index*scale + disp]`; `base` may be rip or a label name.
bool parse_mem(Case &c, std::string text, Operand *out) {
    uint32_t size = 0;
    size_t lb = text.find('[');
    if (lb == std::string::npos) return false;
    std::string pre = trim(text.substr(0, lb));
    if (!pre.empty()) {
        std::istringstream ss(pre);
        std::string kw, ptr;
        ss >> kw >> ptr;
        size = size_of(kw);
        if (!size || ptr != "ptr") return false;
    }
    std::string body = text.substr(lb + 1, text.rfind(']') - lb - 1);
    x86::Gp base, index;
    bool has_base = false, has_index = false, has_rip = false, has_label = false;
    Label lab;
    int64_t disp = 0;
    uint32_t shift = 0;
    // Tokenize into signed terms.
    size_t i = 0;
    while (i < body.size()) {
        int sign = 1;
        while (i < body.size() && (body[i] == ' ' || body[i] == '+' || body[i] == '-')) {
            if (body[i] == '-') sign = -1;
            i++;
        }
        size_t j = i;
        while (j < body.size() && body[j] != '+' && body[j] != '-' && body[j] != ' ') j++;
        std::string term = body.substr(i, j - i);
        i = j;
        if (term.empty()) break;
        size_t star = term.find('*');
        x86::Gp gp;
        x86::Vec vec;
        int bits;
        if (star != std::string::npos) {
            std::string r = term.substr(0, star);
            long sc = strtol(term.c_str() + star + 1, nullptr, 0);
            if (!parse_reg(r, &gp, &vec, &bits)) return false;
            index = gp;
            has_index = true;
            shift = sc == 1 ? 0 : sc == 2 ? 1 : sc == 4 ? 2 : 3;
        } else if (term == "rip") {
            has_rip = true;
        } else if (parse_reg(term, &gp, &vec, &bits)) {
            if (!has_base) base = gp, has_base = true;
            else index = gp, has_index = true;
        } else if (is_number(term)) {
            disp += sign * parse_number(term);
        } else {
            lab = c.label(term);
            has_label = true;
        }
    }
    if (has_rip) *out = x86::ptr(x86::rip, (int32_t)disp, size);
    else if (has_label && has_index) *out = x86::ptr(lab, index, shift, (int32_t)disp, size);
    else if (has_label) *out = x86::ptr(lab, (int32_t)disp, size);
    else if (has_base && has_index) *out = x86::ptr(base, index, shift, (int32_t)disp, size);
    else if (has_base) *out = x86::ptr(base, (int32_t)disp, size);
    else if (has_index) *out = x86::ptr((uint64_t)disp, index, shift, size);
    else *out = x86::ptr((uint64_t)disp, size);
    return true;
}

bool parse_operand(Case &c, const std::string &t, Operand *out) {
    x86::Gp gp;
    x86::Vec vec;
    int bits;
    if (t.find('[') != std::string::npos) return parse_mem(c, t, out);
    if (parse_reg(t, &gp, &vec, &bits)) {
        if (gp.is_valid()) *out = gp; else *out = vec;
        return true;
    }
    if (is_number(t)) return *out = Imm(parse_number(t)), true;
    return *out = c.label(t), true;
}

// Runs one case; returns an error name or "" and fills `hex`.
std::string run_case(const std::string &line, std::string &hex) {
    CodeHolder code;
    if (code.init(Environment::host()) != Error::kOk) return "InitFailed";
    x86::Assembler a(&code);
    a.add_encoding_options(EncodingOptions::kOptimizeForSize | EncodingOptions::kOptimizedAlign);
    Case c{&a, {}};
    std::map<std::string, bool> bound;
    for (const std::string &stmt : split(line, ';')) {
        if (stmt.empty()) continue;
        size_t sp = stmt.find_first_of(" \t");
        std::string mn = sp == std::string::npos ? stmt : stmt.substr(0, sp);
        std::string rest = sp == std::string::npos ? "" : trim(stmt.substr(sp));
        Error err;
        if (mn == "bind") {
            err = a.bind(c.label(rest));
            bound[rest] = true;
        } else if (mn == "align") {
            err = a.align(AlignMode::kCode, (uint32_t)strtoul(rest.c_str(), nullptr, 0));
        } else {
            InstId id = InstAPI::string_to_inst_id(Arch::kX64, mn.c_str(), mn.size());
            if (id == 0) return "UnknownMnemonic:" + mn;
            std::vector<Operand> ops;
            if (!rest.empty())
                for (const std::string &t : split(rest, ',')) {
                    Operand o;
                    if (!parse_operand(c, t, &o)) return "BadOperand:" + t;
                    ops.push_back(o);
                }
            Operand_ none;
            Operand_ o[6];
            for (size_t k = 0; k < 6; k++) o[k] = k < ops.size() ? ops[k] : none;
            err = a.emit(id, o[0], o[1], o[2], o[3], o[4], o[5]);
        }
        if (err != Error::kOk) return DebugUtils::error_as_string(err);
    }
    for (auto &kv : c.labels)
        if (!bound[kv.first]) {
            Error err = a.bind(kv.second);
            if (err != Error::kOk) return DebugUtils::error_as_string(err);
        }
    code.flatten();
    code.resolve_cross_section_fixups();
    CodeBuffer &buf = code.text_section()->buffer();
    char b[4];
    for (size_t i = 0; i < buf.size(); i++) {
        snprintf(b, sizeof b, "%02x", buf.data()[i]);
        hex += b;
    }
    return "";
}

} // namespace

int main() {
    std::string line;
    while (std::getline(std::cin, line)) {
        std::string hex;
        std::string err = run_case(trim(line), hex);
        if (err.empty()) printf("OK %s\n", hex.c_str());
        else printf("ERR %s\n", err.c_str());
        fflush(stdout);
    }
    return 0;
}
