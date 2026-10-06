global::apply_fun_shared:
    mov x2, xzr
    mov x3, x25
    mov x4, x26
    mov x8, x4
    add x9, x19, 64
L100:
    cmp x8, 59
    b.eq L99
    tbnz x8, 1, L101
    sub x8, x8, 1
    ldp x10, x8, [x8]
    str x10, [x9], 8
    add x2, x2, 1
    cmp x2, 1023
    b.lo L100
    mov x8, 15440
    b L102
L101:
    mov x8, 3152
L102:
    mov x25, x3
    mov x26, x4
    str x8, [x21, 96]
    mov x3, 4334029232
    b global::raise_exception
L99:
    lsl x2, x2, 8
    add x2, x2, 20
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    ret x30
global::arith_compare_shared:
    orr x8, x0, x1
    tbnz x8, 0, L103
    ldur x10, [x0, -2]
    ldur x11, [x1, -2]
    mov x12, 88
    cmp x10, x12
    ccmp x11, x12, 0, 2
    b.ne L104
    ldur d0, [x0, 6]
    ldur d1, [x1, 6]
    fcmpe d0, d1
    ret x30
L103:
    and x8, x0, 63
    and x9, x1, 63
    sub x8, x8, 11
    sub x9, x9, 11
    orr x8, x8, x9
    cbnz x8, L104
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    mov x8, 4330899300
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    tst w0, w0
    ret x30
L104:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
# erts_cmp_compound(X, Y, 0, 0);
    mov x2, xzr
    mov x3, xzr
    mov x8, 4331545456
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    tst x0, x0
    ret x30
global::bif_nif_epilogue:
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    mov x14, 4334918068
    ldr w14, [x14]
    cmp x24, 3
    csel x24, x24, x14, 2
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    cbz x0, L105
# Do return and dispatch to it
    mov x25, x0
    ldr x30, [x20], 8
    ret x30
L105:
    ldr x8, [x21, 96]
    cmp x8, 1024
    b.ne L107
# yield
# test trap to hibernate
    ldr w8, [x21, 116]
    tbz x8, 0, L106
# do hibernate trap
    and x8, x8, -2
    str w8, [x21, 116]
    b global::do_schedule
L106:
# do normal trap
    ldr x2, [x21, 240]
    b global::context_switch_simplified
L107:
    mov x1, x20
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x8, 4331091968
    blr x8
    ldp x15, x16, [x19, 96]
    mov x1, x0
    ldr x3, [x21, 456]
    b global::raise_exception_shared
global::bif_export_trap:
    ldr x0, [x21, 456]
    sub x0, x0, 64
    ldr x30, [x20], 8
    ldr x14, [x0, x24 lsl 3]
    br x14
    align 8
global::bif_bit_size_body:
    tbnz x0, 0, L108
    and x10, x0, -8
    ldp x8, x9, [x10]
    cmp x8, 292
    b.ne L109
    ldp x9, x10, [x10, 16]
    sub x9, x10, x9
L109:
    and x8, x8, 56
    cmp x8, 32
    b.ne L108
    lsl x9, x9, 4
    orr x0, x9, 15
    ret x30
L108:
    mov x25, x0
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831016
    b global::raise_exception
global::bif_byte_size_body:
    tbnz x0, 0, L110
    and x10, x0, -8
    ldp x8, x9, [x10]
    cmp x8, 292
    b.ne L111
    ldp x9, x10, [x10, 16]
    sub x9, x10, x9
L111:
    and x8, x8, 56
    cmp x8, 32
    b.ne L110
    add x9, x9, 7
    lsl x9, x9, 1
    orr x0, x9, 15
    ret x30
L110:
    mov x25, x0
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831040
    b global::raise_exception
    align 8
global::bif_element_body_shared:
    tbnz x1, 0, L112
    sub x8, x1, 2
    ldr x9, [x8]
    tst x9, 63
    b.ne L112
    and x10, x0, 15
    cmp x10, 15
    ccmp x0, 15, 4, 2
    b.eq L112
    asr x10, x0, 4
    cmp x10, x9, lsr 6
    b.hi L112
    ldr x0, [x8, x10 lsl 3]
    ret x30
L112:
    mov x25, x0
    mov x26, x1
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831064
    b global::raise_exception
global::bif_element_guard_shared:
    tbnz x1, 0, L113
    sub x8, x1, 2
    ldr x9, [x8]
    tst x9, 63
    b.ne L113
    and x10, x0, 15
    cmp x10, 15
    ccmp x0, 15, 4, 2
    b.eq L113
    asr x10, x0, 4
    cmp x10, x9, lsr 6
    b.hi L113
    ldr x0, [x8, x10 lsl 3]
    ret x30
L113:
    mov x0, xzr
    ret x30
global::bif_is_eq_exact_shared:
    cmp x0, x1
    b.eq L114
    orr x14, x0, x1
    and x14, x14, 3
    cmp x14, 3
    b.eq L115
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    mov x8, 4331543248
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz w0, L115
L114:
    mov x0, 75
    ret x30
L115:
    mov x0, 11
    ret x30
    align 8
global::bif_is_ne_exact_shared:
    cmp x0, x1
    b.eq L117
    orr x14, x0, x1
    and x14, x14, 3
    cmp x14, 3
    b.eq L116
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    mov x8, 4331543248
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbnz w0, L117
L116:
    mov x0, 75
    ret x30
L117:
    mov x0, 11
    ret x30
    align 8
global::bif_tuple_size_body:
    tbnz x0, 0, L118
    ldur x8, [x0, -2]
    tst x8, 63
    b.ne L118
    lsr x8, x8, 2
    orr x0, x8, 15
    ret x30
L118:
    mov x25, x0
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831304
    b global::raise_exception
global::bif_tuple_size_guard:
    tbnz x0, 0, L119
    ldur x8, [x0, -2]
    tst x8, 63
    b.ne L119
    lsr x8, x8, 2
    orr x0, x8, 15
    ret x30
L119:
    mov x0, xzr
    ret x30
    align 8
global::bs_create_bin_error_shared:
    mov x25, x30
    stp x23, x20, [x21, 80]
    mov x1, x3
    mov x3, x0
    mov x0, x21
    mov x8, 4330659124
    blr x8
    ldp x23, x20, [x21, 80]
    mov x3, xzr
    mov x1, x25
    b global::raise_exception_shared
    align 8
global::bs_get_tail_shared:
    and x8, x0, -8
    ldr x3, [x8, 8]
    ldr x1, [x8, 32]
    and x3, x3, -4
    and x2, x1, -8
    and x1, x1, 7
    ldp x4, x8, [x8, 16]
    sub x5, x8, x4
    add x0, x21, 80
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str x23, [x21, 80]
    stp x15, x16, [x19, 96]
    mov x8, 4332244840
    blr x8
    ldr x23, [x21, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
global::bs_get_utf8_shared:
    cls x3, x1
    add x3, x3, 1
    lsl x1, x1, x3
    lsr x1, x1, x3
    mov x11, 64
    sub x11, x11, x3, 3
    lsr x1, x1, x11
    mov x13, 36170084263133184
    lsr x13, x13, x11
    orr x12, x13, x13, lsr 1
    and x10, x1, x12
    cmp x10, x13
    ubfx x8, x1, 8, 6
    ubfx x9, x1, 16, 6
    ubfx x10, x1, 24, 3
    ubfx x1, x1, 0, 6
    orr x1, x1, x8, 6
    orr x1, x1, x9, 12
    orr x1, x1, x10, 18
    mov x8, 1114111
    ccmp x1, x8, 2, 2
    lsr x8, x1, 11
    ccmp x8, 27, 4, 11
    csel x3, x3, xzr, 3
    lsl x8, x3, 2
    cmp x3, 4
    csetm x9, 3
    add x8, x8, x9
    mov x9, 15
    lsr x8, x1, x8
    cmp x8, 0
    sub x8, x3, 2
    ccmp x8, 2, 2, 3
    csel x3, x3, xzr, 11
    csel x9, x9, xzr, 11
    add x2, x2, x3, 3
    str x2, [x0, 16]
    orr x0, x9, x1, 4
    ret x30
global::bs_get_utf8_short_shared:
    lsr x1, x1, 3
    cbz x1, L125
    neg x12, x1, 3
    mov x11, -1
    lsl x11, x11, x12
    ands x8, x2, 7
    cinc x1, x1, 3
    add x9, x3, x2, lsr 3
    cmp x1, 2
    b.eq L120
    b.hi L121
    ldrb w1, [x9]
    b L123
L120:
    ldrh w1, [x9]
    b L123
L121:
    cmp x1, 3
    b.ne L122
    ldrh w1, [x9]
    ldrb w10, [x9, 2]
    orr x1, x1, x10, 16
    b L123
L122:
    ldr w1, [x9]
L123:
    rev64 x1, x1
    lsl x1, x1, x8
    and x1, x1, x11
    tbz x1, 63, L124
    b global::bs_get_utf8_shared
L124:
    add x2, x2, 8
    str x2, [x0, 16]
    mov x0, 15
    orr x0, x0, x1, lsr 52
    ret x30
L125:
    mov x0, xzr
    ret x30
global::bs_init_bits_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    add x2, x19, 48
    add x1, x19, 64
    mov x0, x21
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x8, 4330658488
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ldr w8, [x21, 616]
    tst x8, 2048
    b.ne global::do_schedule
    ret x30
    align 8
global::bs_size_check_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    mov x0, x21
    mov x8, 4330658320
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    mov x3, xzr
    b global::raise_exception
    align 8
global::call_bif_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str x1, [x21, 456]
    ldr w4, [x1, 16]
    strb w4, [x21, 125]
    str x2, [x21, 240]
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    mov x8, 4330657392
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    mov x14, 4334918068
    ldr w14, [x14]
    cmp x24, 3
    csel x24, x24, x14, 2
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    cbz x0, L126
# Do return and dispatch to it
    mov x25, x0
    ldr x30, [x20], 8
    ret x30
L126:
    ldr x8, [x21, 96]
    cmp x8, 1024
    b.ne L128
# yield
# test trap to hibernate
    ldr w8, [x21, 116]
    tbz x8, 0, L127
# do hibernate trap
    and x8, x8, -2
    str w8, [x21, 116]
    b global::do_schedule
L127:
# do normal trap
    ldr x2, [x21, 240]
    b global::context_switch_simplified
L128:
    mov x1, x20
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x8, 4331091968
    blr x8
    ldp x15, x16, [x19, 96]
    mov x1, x0
    ldr x3, [x21, 456]
    b global::raise_exception_shared
    align 8
global::call_light_bif_shared:
    ldr x8, [x21, 536]
    stp x2, x3, [x19, 8]
    str x8, [x19, 24]
    ldr w8, [x3, 36]
    cmp x8, 0
    ccmp x24, 3, 4, 2
    b.eq L129
    subs w22, w22, 1
    b.le L130
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    mov x0, x21
    add x1, x19, 64
    blr x7
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    mov x14, 4334918068
    ldr w14, [x14]
    cmp x24, 3
    csel x24, x24, x14, 2
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ldr w8, [x21, 116]
    tst x8, 3072
    ldr x8, [x21, 576]
    ldr x9, [x21, 520]
    ccmp x9, x8, 2, 2
    sub x8, x20, x23
    asr x8, x8, 3
    ldr x9, [x21, 560]
    ccmp x8, x9, 1, 11
    b.lt L132
L131:
    cbz x0, L134
    mov x25, x0
    ret x30
L134:
    ldr x8, [x21, 96]
    cmp x8, 1024
    b.ne L133
    str x30, [x20, -8]!
    ldr x2, [x21, 240]
    b global::context_switch_simplified
L133:
    ldp x1, x3, [x19, 8]
    add x3, x3, 64
    b global::raise_exception_shared
L132:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    mov x2, x0
    mov x0, x21
    ldr x1, [x19, 24]
    add x3, x19, 64
    ldr x4, [x19, 16]
    ldrb w4, [x4, 80]
    mov x8, 4332207660
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    mov sp, x29
    ldp x29, x30, [sp], 16
    b L131
L129:
    mov x0, x3
    ldr x14, [x0, x24 lsl 3]
    br x14
L130:
    ldrb w1, [x3, 80]
    add x3, x3, 64
    strb w1, [x21, 125]
    str x3, [x21, 456]
    b global::context_switch_simplified
    align 8
global::call_nif_yield_helper:
    subs w22, w22, 1
    b.le L135
    b global::call_nif_shared
L135:
    ldur w8, [x2, -8]
    strb w8, [x21, 125]
    sub x8, x2, 24
    str x8, [x21, 456]
    add x2, x2, 40
    b global::context_switch_simplified
    align 8
global::catch_end_shared:
    mov x25, x26
    cmp x28, 715
    b.ne L136
    ret x30
L136:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    mov x0, x25
    cmp x28, 779
    b.ne L137
    mov x1, x25
    mov x2, x27
    stp x23, x20, [x21, 80]
    mov x0, x21
    mov x8, 4331095540
    blr x8
    ldp x23, x20, [x21, 80]
L137:
    add x2, x23, 56
    cmp x2, x20
    b.ls L138
    mov x25, x0
    mov x3, 1
    bl global::garbage_collect
    mov x0, x25
L138:
    add x25, x23, 2
    mov x8, 128
    mov x9, 1483
    stp x8, x9, [x23], 16
    str x0, [x23], 8
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::call_nif_early:
    mov x1, x30
    sub x1, x1, 52
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x8, 4332480056
    blr x8
    ldp x15, x16, [x19, 96]
    mov x2, x0
    b global::call_nif_shared
    align 8
global::call_nif_shared:
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x1, x2
    add x2, x19, 64
    ldr x3, [x1, 16]
    ldr x4, [x1, 24]
    ldur x5, [x1, 28]
    mov x8, 4330657536
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    mov x14, 4334918068
    ldr w14, [x14]
    cmp x24, 3
    csel x24, x24, x14, 2
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    cbz x0, L139
# Do return and dispatch to it
    mov x25, x0
    ldr x30, [x20], 8
    ret x30
L139:
    ldr x8, [x21, 96]
    cmp x8, 1024
    b.ne L141
# yield
# test trap to hibernate
    ldr w8, [x21, 116]
    tbz x8, 0, L140
# do hibernate trap
    and x8, x8, -2
    str w8, [x21, 116]
    b global::do_schedule
L140:
# do normal trap
    ldr x2, [x21, 240]
    b global::context_switch_simplified
L141:
    mov x1, x20
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x8, 4331091968
    blr x8
    ldp x15, x16, [x19, 96]
    mov x1, x0
    ldr x3, [x21, 456]
    b global::raise_exception_shared
    align 8
global::check_float_error:
    fabs d30, d0
    ldr d31, [L142]
    fcmp d30, d31
    b.hi L143
    ret x30
    align 8
L142:
.xword 0x7FEFFFFFFFFFFFFF
L143:
    mov x3, xzr
    mov x8, 4176
    str x8, [x21, 96]
    b global::raise_exception
global::construct_utf8_shared:
    cmp x0, 2048
    b.hs L144
    ubfiz x8, x0, 8, 6
    mov x9, 32960
    orr x8, x8, x0, lsr 6
    mov x3, 16
    orr x0, x8, x9
    ret x30
L144:
    lsr x8, x0, 16
    cbnz x8, L145
    lsl x8, x0, 2
    ubfiz x9, x0, 16, 6
    and x8, x8, 16128
    mov x3, 24
    orr x8, x8, x0, lsr 12
    orr x8, x8, x9
    mov x9, 8421600
    orr x0, x8, x9
    ret x30
L145:
    lsl x8, x0, 10
    lsr x9, x0, 4
    and x8, x8, 4128768
    and x9, x9, 16128
    bfxil x8, x0, 18, 14
    mov x3, 32
    bfi x8, x0, 24, 6
    orr x8, x8, x9
    mov x9, 2155905264
    orr x0, x8, x9
    ret x30
global::debug_bp:
    ldr x1, [x19, 8]
    sub x1, x1, 36
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x2, x19, 64
    mov x3, 7243
    mov x8, 4331096792
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L146
    ldr x30, [x20], 8
    ldr x14, [x0, x24 lsl 3]
    br x14
L146:
    ldr x1, [x19, 8]
    mov x3, xzr
    b global::raise_exception_shared
global::dispatch_bif:
    ldr x2, [x21, 240]
    sub x1, x2, 24
    ldr x3, [x2, 16]
    b global::call_bif_shared
global::dispatch_nif:
    ldr x2, [x21, 240]
    b global::call_nif_shared
global::dispatch_return:
    mov x2, x30
    str xzr, [x21, 456]
    mov x8, 1
    strb w8, [x21, 125]
    b global::context_switch_simplified
    align 8
global::dispatch_save_calls_export:
    str x0, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    mov x1, x0
    mov x0, x21
    mov x8, 4331499168
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ldr x0, [x19, 8]
    mov x8, 4334918068
    ldr w8, [x8]
    ldr x14, [x0, x8 lsl 3]
    br x14
global::dispatch_save_calls_fun:
    mov x8, 4334918068
    ldr w8, [x8]
    ldr x14, [x0, x8 lsl 3]
    br x14
global::export_trampoline:
    ldr x8, [x0, 96]
    cmp x8, 115
    b.eq global::generic_bp_global
    cmp x8, 32
    b.eq L147
    cmp x8, 34
    b.eq L148
    udf 65535
L147:
    add x1, x0, 64
    ldr x2, [x21, 240]
    ldr x3, [x0, 104]
    str x30, [x20, -8]!
    b global::call_bif_shared
L148:
    add x1, x0, 64
    str x1, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x2, x19, 64
    mov x3, 1035
    mov x8, 4331096792
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ldr x3, [x19, 8]
    cbz x0, global::raise_exception
    ldr x14, [x0, x24 lsl 3]
    br x14
global::fconv_shared:
    tbnz x0, 0, L149
    and x8, x0, -8
    ldr x8, [x8]
    mov x9, 59
    and x9, x8, x9
    cmp x9, 8
    b.ne L149
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    add x1, x19, 8
    mov x8, 4332145640
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    tbnz w0, 31, L149
    ldr d0, [x19, 8]
    ret x30
L149:
    mov x3, xzr
    mov x8, 4176
    str x8, [x21, 96]
    b global::raise_exception
    align 8
global::get_sint64_shared:
    tbnz x0, 0, L151
    ldur x8, [x0, -2]
    ldur x9, [x0, 6]
    and x8, x8, 63
    cmp x8, 8
    b.eq L150
    cmp x8, 12
    b.ne L151
    neg x9, x9
L150:
    mov x0, x9
    tst x8, x8
    ret x30
L151:
    tst xzr, xzr
    ret x30
global::handle_and_error:
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334830992
    b global::raise_exception
global::handle_call_fun_error:
    tbnz x3, 0, L153
    ldurb w8, [x3, -2]
    cmp x8, 20
    b.eq L152
L153:
    mov x8, 10320
    stp x8, x3, [x21, 96]
    mov x1, x4
    mov x3, xzr
    b global::raise_exception_shared
L152:
    stp x3, x4, [x19, 8]
    stp x23, x20, [x21, 80]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    lsr x2, x2, 8
    mov x8, 4330662376
    blr x8
    ldp x23, x20, [x21, 80]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    ldr x25, [x19, 8]
    mov x26, x0
    add x2, x23, 56
    cmp x2, x20
    b.ls L154
    mov x3, 2
    bl global::garbage_collect
L154:
    add x0, x23, 2
    mov x8, 128
    str x8, [x23], 8
    stp x25, x26, [x23], 16
    mov x8, 11344
    stp x8, x0, [x21, 96]
    ldr x1, [x19, 16]
    mov x3, xzr
    b global::raise_exception_shared
    align 8
global::handle_element_error_shared:
    mov x25, x0
    mov x26, x1
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831088
    b global::raise_exception
global::handle_hd_error:
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831112
    b global::raise_exception
global::handle_map_get_badkey:
    mov x8, 19536
    stp x8, x1, [x21, 96]
    mov x25, x1
    mov x26, x0
    mov x3, 4334831160
    b global::raise_exception
global::handle_map_get_badmap:
    mov x8, 18512
    stp x8, x0, [x21, 96]
    mov x25, x1
    mov x26, x0
    mov x3, 4334831136
    b global::raise_exception
global::handle_map_size_error:
    mov x8, 18512
    stp x8, x25, [x21, 96]
    mov x3, 4334831184
    b global::raise_exception
global::handle_node_error:
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831208
    b global::raise_exception
global::handle_not_error:
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831232
    b global::raise_exception
global::handle_or_error:
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831256
    b global::raise_exception
global::handle_tl_error:
    mov x8, 3152
    str x8, [x21, 96]
    mov x3, 4334831280
    b global::raise_exception
global::garbage_collect:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    sub x1, x2, x23
    lsr x1, x1, 3
    sub x1, x1, 4
    str x30, [x21, 240]
    stp x23, x20, [x21, 80]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x2, x19, 64
    mov w4, w22
    mov x8, 4332217108
    blr x8
    sub w22, w22, w0
    ldp x23, x20, [x21, 80]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ldr w8, [x21, 616]
    tst x8, 2048
    b.ne global::do_schedule
    ret x30
global::generic_bp_global:
    str x30, [x20, -8]!
    add x1, x0, 48
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x2, x19, 64
    mov x8, 4331130996
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    ldr x30, [x20], 8
    br x0
global::generic_bp_local:
    ldr x1, [sp, 8]
    str x1, [x19, 8]
    sub x1, x1, 52
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x2, x19, 64
    mov x8, 4331130996
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    cmp x0, 104
    b.eq global::debug_bp
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
global::i_band_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x1, x2, [x19, 8]
    mov x0, x21
    mov x8, 4331807296
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L155
    ret x30
L155:
    ldp x25, x26, [x19, 8]
    mov x3, 4334026176
    b global::raise_exception
    align 8
global::i_bnot_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    eor x1, x0, -16
    str x1, [x19, 8]
    mov x0, x21
    mov x8, 4331812472
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L156
    ret x30
L156:
    ldr x25, [x19, 8]
    mov x3, 4334026248
    b global::raise_exception
global::i_bnot_guard_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    eor x1, x0, -16
    mov x0, x21
    mov x8, 4331812472
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::i_bor_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x1, x2, [x19, 8]
    mov x0, x21
    mov x8, 4331808336
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L157
    ret x30
L157:
    ldp x25, x26, [x19, 8]
    mov x3, 4334026200
    b global::raise_exception
    align 8
global::i_bif_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    str x3, [x19, 8]
    mov x2, xzr
    blr x3
    cbz x0, L158
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
L158:
    ldr x0, [x19, 8]
    mov x8, 4331091840
    blr x8
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldr x27, [x19, 80]
    mov sp, x29
    ldp x29, x30, [sp], 16
    mov x3, x0
    b global::raise_exception
    align 8
global::i_bif_guard_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    mov x2, xzr
    blr x3
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::i_breakpoint_trampoline_shared:
    ldurb w0, [x30, -45]
    cmp x0, 3
    b.eq L159
    tbnz x0, 0, L161
    tbnz x0, 1, L160
    ret x30
L159:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    bl global::generic_bp_local
    mov sp, x29
    ldp x29, x30, [sp], 16
L161:
    b global::call_nif_early
L160:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    bl global::generic_bp_local
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
global::i_bsr_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x1, x2, [x19, 8]
    mov x0, x21
    mov x8, 4331811256
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L162
    ret x30
L162:
    ldp x25, x26, [x19, 8]
    mov x3, 4334026272
    b global::raise_exception
    align 8
global::i_bsl_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x1, x2, [x19, 8]
    mov x0, x21
    mov x8, 4331810384
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L163
    ret x30
L163:
    ldp x25, x26, [x19, 8]
    mov x3, 4334026296
    b global::raise_exception
    align 8
global::i_func_info_shared:
    add x0, x30, 12
    mov x8, 6224
    str x8, [x21, 96]
    str x0, [x21, 456]
    mov x1, xzr
    mov x3, xzr
    b global::raise_exception_shared
    align 8
global::i_get_map_element_shared:
    and x8, x1, 3
    cmp x8, 3
    b.ne L164
    and x0, x0, -8
    ldp x3, x4, [x0]
    and x8, x3, 252
    cmp x8, 44
    b.ne L165
    adds x4, x4, 1
    ldr x8, [x0, 16]!
    and x8, x8, -8
L167:
    sub x4, x4, 1
    cbz x4, L166
    ldr x11, [x8, x4 lsl 3]
    cmp x1, x11
    b.ne L167
    ldr x0, [x0, x4 lsl 3]
L166:
    ret x30
L164:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    mov x8, 4331099944
    blr x8
    ldp x15, x16, [x19, 96]
    cmp x0, 0
    cset x8, 2
    tst x8, x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
L165:
    eor x2, x1, x1, lsr 33
    mov x8, -49064778989728563
    mul x2, x2, x8
    eor x2, x2, x2, lsr 33
    mov x8, -4265267296055464877
    mul x2, x2, x8
    eor x2, x2, x2, lsr 33
    add x0, x0, 16
    mov x12, xzr
L168:
    and x13, x2, 15
    lsr x2, x2, 4
    add x12, x12, 1
    asr w3, w3, 16
    cmn w3, 1
    b.eq L171
    lsr x8, x3, x13
    tbz x8, 0, L169
    lsl x9, x8, x13
    eor x8, x9, x3
    fmov d0, x8
    cnt v0.8b, v0.8b
    addv b0, v0.8b
    fmov x13, d0
L171:
    ldr x8, [x0, x13 lsl 3]
    and x0, x8, -8
    tbnz x8, 0, L170
    ldr x3, [x0], 8
    cmp x12, 16
    b.ne L168
    b L172
L170:
    ldp x8, x0, [x0]
    cmp x8, x1
L169:
    ret x30
L172:
    lsr x8, x3, 3
L173:
    sub x8, x8, 8
    ldr x9, [x0, x8]
    and x9, x9, -8
    ldp x10, x11, [x9]
    cmp x1, x10
    csel x0, x0, x11, 3
    b.eq L169
    cbnz x8, L173
    ret x30
    align 8
global::i_get_map_element_hash_shared:
    and x0, x0, -8
    ldp x3, x4, [x0]
    and x8, x3, 252
    cmp x8, 44
    b.ne L174
    adds x4, x4, 1
    ldr x8, [x0, 16]!
    and x8, x8, -8
L176:
    sub x4, x4, 1
    cbz x4, L175
    ldr x11, [x8, x4 lsl 3]
    cmp x1, x11
    b.ne L176
    ldr x0, [x0, x4 lsl 3]
L175:
    ret x30
L174:
    add x0, x0, 16
    mov x12, xzr
L177:
    and x13, x2, 15
    lsr x2, x2, 4
    add x12, x12, 1
    asr w3, w3, 16
    cmn w3, 1
    b.eq L180
    lsr x8, x3, x13
    tbz x8, 0, L178
    lsl x9, x8, x13
    eor x8, x9, x3
    fmov d0, x8
    cnt v0.8b, v0.8b
    addv b0, v0.8b
    fmov x13, d0
L180:
    ldr x8, [x0, x13 lsl 3]
    and x0, x8, -8
    tbnz x8, 0, L179
    ldr x3, [x0], 8
    cmp x12, 16
    b.ne L177
    b L181
L179:
    ldp x8, x0, [x0]
    cmp x8, x1
L178:
    ret x30
L181:
    lsr x8, x3, 3
L182:
    sub x8, x8, 8
    ldr x9, [x0, x8]
    and x9, x9, -8
    ldp x10, x11, [x9]
    cmp x1, x10
    csel x0, x0, x11, 3
    b.eq L178
    cbnz x8, L182
    ret x30
    align 8
global::i_length_guard_shared:
    stp x1, x2, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x8, x19, 64
    add x1, x8, x1, 3
    mov x8, 4331355032
    blr x8
    cbz x0, L184
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
L184:
    ldp x1, x2, [x19, 8]
    ldr x8, [x21, 96]
    cmp x8, 1024
    b.ne L183
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    add x1, x1, 2
    str xzr, [x21, 456]
    strb w1, [x21, 125]
    b global::context_switch_simplified
L183:
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::i_length_body_shared:
    stp x1, x2, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x8, x19, 64
    add x1, x8, x1, 3
    mov x8, 4331355032
    blr x8
    cbz x0, L186
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
L186:
    ldp x1, x2, [x19, 8]
    ldr x8, [x21, 96]
    cmp x8, 1024
    b.ne L185
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    add x1, x1, 3
    str xzr, [x21, 456]
    strb w1, [x21, 125]
    b global::context_switch_simplified
L185:
    add x8, x19, 64
    add x1, x8, x1, 3
    ldr x8, [x1, 16]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    mov x25, x8
    mov x3, 4334027800
    mov x1, x30
    b global::raise_exception_shared
    align 8
global::i_line_breakpoint_trampoline_shared:
    str x30, [x20, -8]!
    str x8, [x19, 8]
    sub x0, x30, 8
    str x0, [x19, 16]
    mov x3, x8
    lsl x8, x8, 3
    str x8, [x19, 24]
    add x2, x8, 32
    add x2, x2, x23
    cmp x2, x20
    b.ls L189
    bl global::garbage_collect
    ldr x8, [x19, 24]
L189:
    sub x20, x20, x8
    mov x0, x21
    ldr x1, [x19, 16]
    ldr x2, [x19, 8]
    add x3, x19, 64
    mov x4, x20
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x8, 4331138220
    blr x8
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    cbnz x0, L190
    ldr x0, [x19, 24]
    b L188
L190:
    ldr x8, [x0, x24 lsl 3]
    blr x8
global::i_line_breakpoint_cleanup:
    add x0, x19, 64
    mov x1, x20
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x8, 4331138696
    blr x8
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    lsl x0, x0, 3
L188:
    add x20, x20, x0
L187:
    ldr x30, [x20], 8
    ret x30
global::i_loop_rec_shared:
    mov x26, x30
    ldr w8, [x21, 116]
    orr x8, x8, 8192
    str w8, [x21, 116]
    str x0, [x21, 240]
    str x1, [x19, 8]
L191:
    tst w22, w22
    b.le L193
# Peek next message
L192:
    ldr x8, [x21, 320]
    ldr x0, [x8]
    cbnz x0, L194
# Inner queue empty, fetch more from outer/middle queues
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    str xzr, [x19, 16]
    mov x0, x21
    mov w1, w22
    mov x2, xzr
    add x3, x19, 16
    add x4, x19, 24
    mov x8, 4331763660
    blr x8
    ldp x23, x20, [x21, 80]
    mov x14, 4334918068
    ldr w14, [x14]
    cmp x24, 3
    csel x24, x24, x14, 2
    sub w22, w22, w0
    ldr x0, [x19, 16]
    cbnz x0, L194
    ldr w8, [x19, 24]
    cbnz x8, L193
    ldr w8, [x21, 116]
    and x8, x8, -8193
    str w8, [x21, 116]
    ldr x8, [x19, 8]
    br x8
L193:
    ldr w8, [x21, 116]
    and x8, x8, -8193
    str w8, [x21, 116]
    strb wzr, [x21, 125]
    str xzr, [x21, 456]
    b global::do_schedule
# Check if message is distributed
L194:
    ldr x8, [x0, 16]
    cbnz x8, L195
    sub w22, w22, 10
    mov x1, x0
    mov x0, x21
    mov x8, 4330660096
    blr x8
    cbz x0, L191
L195:
    ldr x25, [x0, 16]
    ret x26
global::i_test_yield_shared:
    sub x1, x2, 24
    add x2, x2, 24
    str x1, [x21, 456]
    ldr w1, [x1, 16]
    strb w1, [x21, 125]
    b global::context_switch_simplified
global::i_bxor_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x1, x2, [x19, 8]
    mov x0, x21
    mov x8, 4331809380
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L196
    ret x30
L196:
    ldp x25, x26, [x19, 8]
    mov x3, 4334026224
    b global::raise_exception
    align 8
global::int128_to_big_shared:
    extr x2, x9, x0, 4
    asr x3, x9, 4
    mov x0, x21
    cmp x3, 0
    cset x1, 6
    b.pl L197
    negs x2, x2
    ngc x3, x3
L197:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    mov x8, 4330659736
    blr x8
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::int_div_rem_body_shared:
    asr x8, x1, 4
    asr x9, x2, 4
    sdiv x10, x8, x9
    msub x11, x10, x9, x8
    cmp x2, 15
    b.eq L198
    and x8, x1, x2
    and x8, x8, 15
    cmp x8, 15
    b.ne L199
    asr x8, x10, 59
    cmp x8, 1
    b.ge L199
    mov x8, 15
    orr x0, x8, x10, 4
    orr x1, x8, x11, 4
    ret x30
L199:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    stp x1, x2, [x19, 8]
    str x3, [x19, 24]
    mov x0, x21
    add x3, x19, 32
    add x4, x19, 40
    mov x8, 4331805832
    blr x8
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    tst x0, x0
    ldp x0, x1, [x19, 32]
    b.eq L200
    ret x30
L198:
    mov x8, 4176
    str x8, [x21, 96]
    mov x25, x1
    mov x26, x2
    b global::raise_exception
L200:
    ldp x25, x26, [x19, 8]
    ldr x3, [x19, 24]
    b global::raise_exception
global::int_div_rem_guard_shared:
    asr x8, x1, 4
    asr x9, x2, 4
    sdiv x10, x8, x9
    msub x11, x10, x9, x8
    cmp x2, 15
    b.eq L201
    and x8, x1, x2
    and x8, x8, 15
    cmp x8, 15
    b.ne L202
    asr x8, x10, 59
    cmp x8, 1
    b.ge L202
    mov x8, 15
    orr x0, x8, x10, 4
    orr x1, x8, x11, 4
L201:
    ret x30
L202:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x3, x19, 32
    add x4, x19, 40
    mov x8, 4331805832
    blr x8
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    tst x0, x0
    ldp x0, x1, [x19, 32]
    ret x30
    align 8
global::is_eq_exact_list_shared:
    b L204
L203:
    and x0, x0, -8
    and x1, x1, -8
    ldp x8, x0, [x0]
    ldp x9, x1, [x1]
    cmp x8, x9
    b.ne L205
L204:
    cmp x0, x1
    b.eq L205
    orr x8, x0, x1
    tbz x8, 1, L203
    cmp x8, 0
L205:
    ret x30
    align 8
global::is_eq_exact_shallow_boxed_shared:
    orr x8, x0, x1
    tbnz x8, 0, L208
    and x8, x0, -8
    ldr x10, [x8]
    and x9, x1, -8
    lsr x2, x10, 6
    sub x2, x2, 1
L206:
    ldp x10, x11, [x8], 16
    ldp x12, x13, [x9], 16
    cmp x10, x12
    ccmp x11, x13, 0, 2
    b.ne L207
    subs x2, x2, 2
    b.pl L206
    cmn x2, 2
    b.eq L207
    ldr x10, [x8]
    ldr x12, [x9]
    cmp x10, x12
L207:
    ret x30
L208:
    cmp x8, 0
    ret x30
global::is_in_range_shared:
    tbnz x0, 0, L209
    ldur x9, [x0, -2]
    mov x10, 88
    cmp x9, x10
    b.ne L210
    ldur d0, [x0, 6]
    asr x8, x1, 4
    scvtf d1, x8
    fcmpe d0, d1
    b.mi L211
    asr x8, x2, 4
    scvtf d1, x8
    fcmpe d0, d1
    b.gt L211
    tst xzr, xzr
L211:
    ret x30
L209:
    mov x8, 1
    cmp x8, 0
    ret x30
L210:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    stp x0, x2, [x19, 8]
# erts_cmp_compound(X, Y, 0, 0);
    mov x2, xzr
    mov x3, xzr
    mov x8, 4331545456
    blr x8
    tst x0, x0
    b.mi L212
    ldp x0, x1, [x19, 8]
# erts_cmp_compound(X, Y, 0, 0);
    mov x2, xzr
    mov x3, xzr
    mov x8, 4331545456
    blr x8
    tst x0, x0
L212:
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::is_ge_lt_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x15, x16, [x19, 96]
    stp x0, x2, [x19, 8]
# erts_cmp_compound(Src, A, 0, 0);
    mov x2, xzr
    mov x3, xzr
    mov x8, 4331545456
    blr x8
    tst x0, x0
    b.mi L213
# erts_cmp_compound(B, Src, 0, 0);
    ldp x1, x0, [x19, 8]
    mov x2, xzr
    mov x3, xzr
    mov x8, 4331545456
    blr x8
    cmp x0, 0
    cset x0, 3
    csinv x0, x0, xzr, 12
    adds x0, x0, 1
L213:
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::minus_body_shared:
    stp x1, x2, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    mov x0, x21
    mov x8, 4331802404
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L214
    ret x30
L214:
    ldp x25, x26, [x19, 8]
    mov x3, 4334025984
    b global::raise_exception
    align 8
global::mul_add_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    stp x1, x2, [x19, 8]
    mov x0, x21
    cmp x3, 15
    b.eq L215
    str x3, [x19, 32]
    add x4, x19, 24
    mov x8, 4331811784
    blr x8
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L216
    ret x30
L215:
    mov x8, 4331803584
    blr x8
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L217
    ret x30
L216:
    ldp x25, x26, [x19, 24]
    mov x3, 4334026032
    cbnz x25, L218
L217:
    ldp x25, x26, [x19, 8]
    mov x3, 4334026008
L218:
    b global::raise_exception
global::mul_add_guard_shared:
    str x3, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x8, 4331803584
    blr x8
    cbz x0, L219
    ldr x2, [x19, 8]
    mov x1, x0
    mov x0, x21
    mov x8, 4331800544
    blr x8
L219:
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::mul_body_shared:
    mov x3, 15
    b global::mul_add_body_shared
global::mul_guard_shared:
    mov x3, 15
    b global::mul_add_guard_shared
global::new_map_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    mov x8, 4331100504
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::plus_body_shared:
    stp x1, x2, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    mov x0, x21
    mov x8, 4331800544
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L220
    ret x30
L220:
    ldp x25, x26, [x19, 8]
    mov x3, 4334025936
    b global::raise_exception
    align 8
global::process_exit:
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x1, xzr
    mov x3, xzr
    add x2, x19, 64
    mov x8, 4331092144
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x15, x16, [x19, 96]
    cbz x0, global::do_schedule
    udf 57005
global::process_main:
    stp x29, x30, [sp, -16]!
    mov x8, sp
    sub x8, x8, 208
    sub x8, x8, 16384
    and x8, x8, -64
    mov sp, x8
    mov x29, sp
    str x8, [x0]
    mov x19, sp
    str xzr, [x19, 16512]
    str xzr, [x19, 16520]
    mov x21, xzr
    mov w22, wzr
    mov x2, xzr
    b L224
L223:
    ldr x8, [x21, 176]
    sub w2, w8, w22
    b L224
L221:
# Context switch, unknown arity/MFA
    ldur w8, [x2, -8]
    strb w8, [x21, 125]
    sub x8, x2, 24
    str x8, [x21, 456]
L222:
# Context switch, known arity and MFA
    str x2, [x21, 240]
    ldr w8, [x21, 616]
    tst x8, 2048
    b.eq L225
# Process exiting
    adr x8, global::process_exit
    str x8, [x21, 240]
    strb wzr, [x21, 125]
    str xzr, [x21, 456]
    b L223
L225:
    ldr w8, [x21, 176]
    sub w22, w8, w22
# Copy out X registers
    mov x0, x21
    add x1, x19, 64
    mov x8, 4331091460
    blr x8
    mov w2, w22
L224:
# schedule_next
    ldr x8, [x19, 16520]
    cbz x8, L226
    mov x0, x21
    ldr x1, [x19, 16520]
    str x2, [x19, 16520]
    ldr x2, [x19, 16512]
    mov x8, 4331091704
    blr x8
    ldr x2, [x19, 16520]
L226:
    mov x0, xzr
    mov x1, x21
    mov x8, 4330463700
    blr x8
    mov x21, x0
    str xzr, [x19, 16520]
    mov x0, 4334829712
    ldr x8, [x0]
    cbz x8, L227
    mov x8, 4331558768
    blr x8
    str x0, [x19, 16520]
    ldr x8, [x21, 240]
    str x8, [x19, 16512]
L227:
# skip_long_schedule
    mov x0, x21
    add x1, x19, 64
    mov x8, 4331091676
    blr x8
    ldr w22, [x21, 112]
    str x22, [x21, 176]
# check whether save calls is on
    mov x0, x21
    mov x1, 1
    mov x8, 4330674260
    blr x8
    mov x8, 4334918068
    ldr w8, [x8]
    mov x9, 3
    cmp x0, xzr
    csel x24, x8, x9, 2
    ldp x23, x20, [x21, 80]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    ldr x0, [x21, 240]
    ldr x8, [x0]
    cmp x8, 36
    b.eq global::dispatch_nif
    cmp x8, 32
    b.eq global::dispatch_bif
    br x0
global::context_switch:
    stp x23, x20, [x21, 80]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    b L221
global::context_switch_simplified:
    stp x23, x20, [x21, 80]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    b L222
global::do_schedule:
    stp x23, x20, [x21, 80]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    b L223
global::raise_exception:
    mov x1, x30
    b global::raise_exception_shared
global::raise_exception_null_exp:
    mov x3, xzr
    mov x1, x30
    b global::raise_exception_shared
    align 8
global::raise_exception_shared:
    str x1, [x20, -8]!
    stp x23, x20, [x21, 80]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    tst x1, 3
    b.ne L228
    mov x0, x21
    add x2, x19, 64
    mov x8, 4331092144
    blr x8
    ldp x23, x20, [x21, 80]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    cbz x0, global::do_schedule
    br x0
L228:
    udf 2989
global::raise_shared:
    str x0, [x21, 104]
    str x1, [x21, 280]
    mov x0, x21
    mov x8, 4331096588
    blr x8
    mov x3, xzr
    mov x1, x30
    b global::raise_exception_shared
global::store_unaligned:
    ldrb w12, [x8]
    and x11, x7, 255
    lsr x11, x11, x2
    lsl x12, x12, x2
    and x12, x12, -256
    lsr x12, x12, x2
    orr x12, x11, x12
    strb w12, [x8], 1
    mov x13, 8
    sub x13, x13, x2
    rev64 x7, x7
    lsl x7, x7, x13
    subs x3, x3, x13
    b.le L230
L229:
    ror x7, x7, 56
    strb w7, [x8], 1
    subs x3, x3, 8
    b.gt L229
L230:
    ret x30
    align 8
global::unloaded_fun:
    str x4, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    lsr x2, x2, 8
    mov x4, x24
    mov x8, 4330662636
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    mov x14, 4334918068
    ldr w14, [x14]
    cmp x24, 3
    csel x24, x24, x14, 2
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L231
    ldr x8, [x0, x24 lsl 3]
    br x8
L231:
    ldr x1, [x19, 8]
    mov x3, xzr
    b global::raise_exception_shared
    align 8
global::unary_minus_body_shared:
    str x1, [x19, 8]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    mov x0, x21
    mov x8, 4331801744
    blr x8
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L232
    ret x30
L232:
    ldr x25, [x19, 8]
    mov x3, 4334025960
    b global::raise_exception
    align 8
global::update_map_assoc_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    mov x8, 4331101304
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::update_map_single_assoc_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    mov x8, 4332540536
    blr x8
    ldp x23, x20, [x21, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
global::update_map_exact_guard_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    mov x8, 4331103060
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    ret x30
    align 8
global::update_map_exact_body_shared:
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    str w22, [x21, 112]
    stp x25, x26, [x19, 64]
    stp x27, x28, [x19, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x1, x19, 64
    mov x8, 4331103060
    blr x8
    ldp x23, x20, [x21, 80]
    ldr w22, [x21, 112]
    ldp x25, x26, [x19, 64]
    ldp x27, x28, [x19, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz x0, L233
    ret x30
L233:
    mov x3, xzr
    b global::raise_exception
global::update_map_single_exact_body_shared:
    str x1, [x19, 16]
    stp x29, x30, [sp, -16]!
    mov x29, sp
    stp x23, x20, [x21, 80]
    stp x15, x16, [x19, 96]
    mov x0, x21
    add x4, x19, 8
    mov x8, 4332547896
    blr x8
    ldp x23, x20, [x21, 80]
    ldp x15, x16, [x19, 96]
    mov sp, x29
    ldp x29, x30, [sp], 16
    cbz w0, L234
    ldr x0, [x19, 8]
    ret x30
L234:
    ldr x9, [x19, 16]
    mov x8, 19536
    stp x8, x9, [x21, 96]
    mov x3, xzr
    b global::raise_exception
