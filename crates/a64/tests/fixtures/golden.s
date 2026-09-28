.text
add x0, x1, #4095
adds w2, w3, #7
sub x4, x5, #1, lsl #12
subs x6, x7, x8, lsr #3
adc x9, x10, x11
and x12, x13, #255
orr x14, x15, x16
bfi x17, x18, #4, #8
movz x19, #0xabcd, lsl #32
ldr x20, [x21, #32760]
str w22, [sp, #4092]
ldur x23, [x24, #-256]
stur w25, [x26, #255]
ldp x27, x28, [sp, #-16]!
stp x29, x30, [sp], #16
ldr x0, [x1, x2, lsl #3]
b .+16
bl .-8
b.eq .+12
cbnz w4, .-16
tbz x5, #42, .+28
br x6
adr x7, #12
csel x8, x9, x10, ge
mul x11, x12, x13
sdiv x14, x15, x16
rev64 x17, x18
nop
udf #0xbeef
ldrb w0, [x1, #4095]
strh w2, [x3, #8190]
ldurb w4, [x5, #-1]
sturh w6, [x7, #2]
ldaxr x8, [x9]
stlxr w10, x11, [x12]
ldaddal x13, x14, [x15]
ldr d16, [x17, #32760]
str d18, [x19, #8]
fmov d20, d21
fabs d22, d23
fneg d24, d25
fcmp d26, d27
fcmpe d28, d29
scvtf d30, x0
cnt v1.8b, v2.8b
addv b3, v4.8b
movi v0.16b, #255
movi v1.8b, #1
lsl x2, x3, x4
lsr w5, w6, w7
asr x8, x9, x10
ror x11, x12, x13
ror x14, x15, #7
ccmp x1, #3, #4, eq
ccmn w2, #5, #6, ne
fmov d0, x1
fmov x2, d3
movn x0, #0
movz x1, #0xdef0
movk x1, #0x9abc, lsl #16
movk x1, #0x5678, lsl #32
movk x1, #0x1234, lsl #48
movn w2, #0
movz x3, #0
adds x0, x1, x2, lsl #1
sub w3, w4, w5, asr #2
add x6, x7, w8, uxtw #3
sub x9, x10, x11, sxtx
cmn x12, #255
cmp w13, w14, lsl #2
tst x15, #0xff
ccmp x16, x17, #5, ne
ccmn x18, x19, #6, eq
neg x20, x21
negs w22, w23
ngc x24, x25
ands x26, x27, x28, ror #4
eor w0, w1, #0xff00ff00
lsr x2, x3, #63
ubfx x4, x5, #8, #16
ubfiz x6, x7, #4, #8
sbfx x8, x9, #3, #12
bfxil x10, x11, #5, #7
smulh x12, x13, x14
madd x15, x16, x17, x18
msub w19, w20, w21, w22
udiv x23, x24, x25
rev16 w26, w27
rev32 x28, x29
cls w30, w0
cset x1, eq
csetm w2, hi
cinc x3, x4, ne
csinv x5, x6, x7, lt
cbz x8, .+12
tbnz w9, #31, .-8
blr x10
ret x30
ldr w11, [x12, #4092]
stur x13, [x14, #-8]
ldp w15, w16, [x17, #12]
stp x18, x19, [sp, #-16]
ldr x0, .+8
ldr x1, [x2], #8
str x3, [x4], #-8
ldr x5, [x6, #-8]!
str w7, [x8, #4]!
sturb w9, [x10, #-3]
ldurh w11, [x12, #2]
adr x13, .-4
.long 0x12345678
.quad 0x123456789abcdef0
movi v0.2d, #0xffffffffffffffff
movi v31.2d, #0
movi d31, #0
add x0, x1, x2
subs x3, x4, #5
and x5, x6, x7
orr x8, x9, #0xff
eor x10, x11, x12
tst x13, x14
cmp x15, #3
strb w16, [x17, #4095]
ldrh w18, [x19, #8190]
lsl x20, x21, #0
asr w22, w23, #31
extr x24, x25, x26, #7
