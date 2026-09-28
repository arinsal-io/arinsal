.text
fmov d0, d1
fmov d2, x3
fmov x4, d5
fmov d6, #1.0
fabs d7, d8
fneg d9, d10
fadd d11, d12, d13
fsub d14, d15, d16
fmul d17, d18, d19
fdiv d20, d21, d22
fsqrt d23, d24
fcmp d25, d26
fcmpe d27, d28
scvtf d29, x30
fcvtzs x0, d1
fcvtzs w2, d3
fcvtms x4, d5
fcvtms w6, d7
fcvtps x8, d9
fcvtps w10, d11
frintz d12, d13
frintm d14, d15
frintp d16, d17
fccmp d18, d19, #7, ge
fcsel d20, d21, d22, lt
ldr d0, [x1, #24]
str d2, [x3, #32]
ldur d4, [x5, #-8]
stur d6, [x7, #16]
ldr d8, [x9, #8]!
str d10, [x11, #-16]!
ldr d12, [x13], #24
str d14, [x15], #-8
ldr d16, [x17, x18]
str d19, [x20, x21, lsl #3]
ldp d22, d23, [x24, #16]
stp d25, d26, [x27, #-16]
ldp d0, d1, [x2, #-16]!
stp d3, d4, [x5, #16]!
ldp d6, d7, [x8], #16
stp d9, d10, [x11], #-16
ldr d11, #8
cnt v12.8b, v13.8b
addv b14, v15.8b
movi v16.16b, #0x5a
ldr q0, [x1, #16]
str q2, [x3, #32]
ldur q4, [x5, #-16]
stur q6, [x7, #16]
ldr q8, [x9, #16]!
str q10, [x11, #-16]!
ldr q12, [x13], #24
str q14, [x15], #-8
ldp q16, q17, [x18, #32]
stp q19, q20, [x21, #-32]
ldp q22, q23, [x24, #-32]!
stp q25, q26, [x27, #32]!
ldp q28, q29, [x0], #32
stp q30, q31, [x1], #-32
