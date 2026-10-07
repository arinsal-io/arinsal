# kernels:tail/1
# i_func_label [SmallInt(1)]
# func_line [SmallInt(1)]
# i_func_info [SmallInt(1), Atom(1), Atom(2), SmallInt(1)]
    00000000: d503201f  nop
# aligned_label [SmallInt(2), SmallInt(4)]
# i_breakpoint_trampoline []
    00000004: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    00000008: 710006d6  subs w22, w22, #0x1
    0000000c: 5400008c  b.gt 0x1c <ltmp0+0x1c>
    00000010: 10000068  adr x8, 0x1c <ltmp0+0x1c>
    00000014: f90026a8  str x8, [x21, #0x48]
    00000018: 140002d5  b 0xb6c <ltmp0+0xb6c>
# i_move [SmallInt(0), X(1)]
    0000001c: d28001fa  mov x26, #0xf ; =15
# i_call_only [Label(4)]
    00000020: f840869e  ldr x30, [x20], #0x8
    00000024: 710006d6  subs w22, w22, #0x1
    00000028: 540000a5  b.pl 0x3c <ltmp0+0x3c>
    0000002c: 10000088  adr x8, 0x3c <ltmp0+0x3c>
    00000030: f90026a8  str x8, [x21, #0x48]
    00000034: 140002ce  b 0xb6c <ltmp0+0xb6c>
# i_flush_stubs []
# kernels:tail_loop/2
# i_func_label [SmallInt(3)]
# func_line [SmallInt(2)]
# i_func_info [SmallInt(3), Atom(1), Atom(3), SmallInt(2)]
    00000038: d503201f  nop
# aligned_label [SmallInt(4), SmallInt(4)]
# i_breakpoint_trampoline []
    0000003c: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    00000040: 710006d6  subs w22, w22, #0x1
    00000044: 5400008c  b.gt 0x54 <ltmp0+0x54>
    00000048: 10000068  adr x8, 0x54 <ltmp0+0x54>
    0000004c: f90026a8  str x8, [x21, #0x48]
    00000050: 140002c7  b 0xb6c <ltmp0+0xb6c>
# is_eq_exact [Label(5), X(0), SmallInt(0)]
    00000054: f1003f3f  cmp x25, #0xf
    00000058: 54000121  b.ne 0x7c <ltmp0+0x7c>
# i_move [X(1), X(0)]
    0000005c: aa1a03f9  mov x25, x26
# return []
    00000060: f840869e  ldr x30, [x20], #0x8
    00000064: 710006d6  subs w22, w22, #0x1
    00000068: f90026be  str x30, [x21, #0x48]
    0000006c: 54000045  b.pl 0x74 <ltmp0+0x74>
    00000070: 140002bf  b 0xb6c <ltmp0+0xb6c>
    00000074: aa1f03e0  mov x0, xzr
    00000078: d65f03c0  ret
# label [SmallInt(5)]
# line [SmallInt(3)]
# i_minus [Label(0), SmallInt(2), X(0), SmallInt(1), X(0)]
    0000007c: f1004320  subs x0, x25, #0x10
    00000080: 92400f28  and x8, x25, #0xf
    00000084: fa4f7900  ccmp x8, #0xf, #0x0, vc
    00000088: 54000280  b.eq 0xd8 <ltmp0+0xd8>
    0000008c: aa1903ee  mov x14, x25
    00000090: d28003f1  mov x17, #0x1f ; =31
    00000094: d2800028  mov x8, #0x1 ; =1
    00000098: b90022b6  str w22, [x21, #0x20]
    0000009c: a902426f  stp x15, x16, [x19, #0x20]
    000000a0: aa1503e0  mov x0, x21
    000000a4: aa0803e1  mov x1, x8
    000000a8: aa0e03e2  mov x2, x14
    000000ac: aa1103e3  mov x3, x17
    000000b0: d2879491  mov x17, #0x3ca4 ; =15524
    000000b4: f2a05e11  movk x17, #0x2f0, lsl #16
    000000b8: f2c00031  movk x17, #0x1, lsl #32
    000000bc: f90026be  str x30, [x21, #0x48]
    000000c0: d63f0220  blr x17
    000000c4: b94022b6  ldr w22, [x21, #0x20]
    000000c8: a942426f  ldp x15, x16, [x19, #0x20]
    000000cc: f94026be  ldr x30, [x21, #0x48]
    000000d0: f94016a9  ldr x9, [x21, #0x28]
    000000d4: b50055c9  cbnz x9, 0xb8c <ltmp0+0xb8c>
    000000d8: aa0003f9  mov x25, x0
# i_plus [Label(0), SmallInt(2), X(1), SmallInt(1), X(1)]
    000000dc: b1004340  adds x0, x26, #0x10
    000000e0: 92400f48  and x8, x26, #0xf
    000000e4: fa4f7900  ccmp x8, #0xf, #0x0, vc
    000000e8: 54000280  b.eq 0x138 <ltmp0+0x138>
    000000ec: aa1a03ee  mov x14, x26
    000000f0: d28003f1  mov x17, #0x1f ; =31
    000000f4: d2800008  mov x8, #0x0 ; =0
    000000f8: b90022b6  str w22, [x21, #0x20]
    000000fc: a902426f  stp x15, x16, [x19, #0x20]
    00000100: aa1503e0  mov x0, x21
    00000104: aa0803e1  mov x1, x8
    00000108: aa0e03e2  mov x2, x14
    0000010c: aa1103e3  mov x3, x17
    00000110: d2879491  mov x17, #0x3ca4 ; =15524
    00000114: f2a05e11  movk x17, #0x2f0, lsl #16
    00000118: f2c00031  movk x17, #0x1, lsl #32
    0000011c: f90026be  str x30, [x21, #0x48]
    00000120: d63f0220  blr x17
    00000124: b94022b6  ldr w22, [x21, #0x20]
    00000128: a942426f  ldp x15, x16, [x19, #0x20]
    0000012c: f94026be  ldr x30, [x21, #0x48]
    00000130: f94016a9  ldr x9, [x21, #0x28]
    00000134: b50052c9  cbnz x9, 0xb8c <ltmp0+0xb8c>
    00000138: aa0003fa  mov x26, x0
# i_call_only [Label(4)]
    0000013c: f840869e  ldr x30, [x20], #0x8
    00000140: 710006d6  subs w22, w22, #0x1
    00000144: 54fff7c5  b.pl 0x3c <ltmp0+0x3c>
    00000148: 10fff7a8  adr x8, 0x3c <ltmp0+0x3c>
    0000014c: f90026a8  str x8, [x21, #0x48]
    00000150: 14000287  b 0xb6c <ltmp0+0xb6c>
# i_flush_stubs []
# kernels:list/1
# i_func_label [SmallInt(6)]
# func_line [SmallInt(4)]
# i_func_info [SmallInt(6), Atom(1), Atom(7), SmallInt(1)]
    00000154: d503201f  nop
# aligned_label [SmallInt(7), SmallInt(4)]
# i_breakpoint_trampoline []
    00000158: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    0000015c: 710006d6  subs w22, w22, #0x1
    00000160: 5400008c  b.gt 0x170 <ltmp0+0x170>
    00000164: 10000068  adr x8, 0x170 <ltmp0+0x170>
    00000168: f90026a8  str x8, [x21, #0x48]
    0000016c: 14000280  b 0xb6c <ltmp0+0xb6c>
# allocate_heap [SmallInt(2), Allocations([(0, 0), (1, 0), (2, 2)]), SmallInt(1)]
    00000170: 9100c2e8  add x8, x23, #0x30
    00000174: eb14011f  cmp x8, x20
    00000178: 54000269  b.ls 0x1c4 <ltmp0+0x1c4>
    0000017c: a90052b7  stp x23, x20, [x21]
    00000180: f9000279  str x25, [x19]
    00000184: f90026be  str x30, [x21, #0x48]
    00000188: aa1503e0  mov x0, x21
    0000018c: aa1303e1  mov x1, x19
    00000190: d2800082  mov x2, #0x4 ; =4
    00000194: d2800023  mov x3, #0x1 ; =1
    00000198: 2a1603e4  mov w4, w22
    0000019c: d2876691  mov x17, #0x3b34 ; =15156
    000001a0: f2a05e11  movk x17, #0x2f0, lsl #16
    000001a4: f2c00031  movk x17, #0x1, lsl #32
    000001a8: d63f0220  blr x17
    000001ac: a94052b7  ldp x23, x20, [x21]
    000001b0: f9400279  ldr x25, [x19]
    000001b4: 4b0002d6  sub w22, w22, w0
    000001b8: f94026be  ldr x30, [x21, #0x48]
    000001bc: f94016a9  ldr x9, [x21, #0x28]
    000001c0: b5004e69  cbnz x9, 0xb8c <ltmp0+0xb8c>
    000001c4: d1004294  sub x20, x20, #0x10
# i_move [Literal(4294967295), Y(1)]
    000001c8: d29c0349  mov x9, #0xe01a ; =57370
    000001cc: f2a07e29  movk x9, #0x3f1, lsl #16
    000001d0: f2c00109  movk x9, #0x8, lsl #32
    000001d4: f9000689  str x9, [x20, #0x8]
# i_move [Literal(4294967294), Y(0)]
    000001d8: d29c0549  mov x9, #0xe02a ; =57386
    000001dc: f2a07e29  movk x9, #0x3f1, lsl #16
    000001e0: f2c00109  movk x9, #0x8, lsl #32
    000001e4: f9000289  str x9, [x20]
# i_move [X(0), X(1)]
    000001e8: aa1903fa  mov x26, x25
# i_move [SmallInt(1), X(0)]
    000001ec: d28003f9  mov x25, #0x1f ; =31
# line [SmallInt(5)]
# i_call_ext [SmallInt(2)]
    000001f0: 1000011e  adr x30, 0x210 <ltmp0+0x210>
    000001f4: d292560d  mov x13, #0x92b0 ; =37552
    000001f8: f2bfd58d  movk x13, #0xfeac, lsl #16
    000001fc: f2c000ed  movk x13, #0x7, lsl #32
    00000200: f94001ae  ldr x14, [x13]
    00000204: aa1503e0  mov x0, x21
    00000208: aa0d03e1  mov x1, x13
    0000020c: d63f01c0  blr x14
# i_move [X(0), X(1)]
    00000210: aa1903fa  mov x26, x25
# move_trim [Y(0), X(0), SmallInt(1)]
    00000214: f9400299  ldr x25, [x20]
    00000218: 91002294  add x20, x20, #0x8
# i_call_ext [SmallInt(3)]
    0000021c: 1000011e  adr x30, 0x23c <ltmp0+0x23c>
    00000220: d2925a0d  mov x13, #0x92d0 ; =37584
    00000224: f2bfd58d  movk x13, #0xfeac, lsl #16
    00000228: f2c000ed  movk x13, #0x7, lsl #32
    0000022c: f94001ae  ldr x14, [x13]
    00000230: aa1503e0  mov x0, x21
    00000234: aa0d03e1  mov x1, x13
    00000238: d63f01c0  blr x14
# i_move [SmallInt(0), X(1)]
    0000023c: d28001fa  mov x26, #0xf ; =15
# i_move [X(0), X(2)]
    00000240: aa1903fb  mov x27, x25
# move_call_ext_last [Y(0), X(0), SmallInt(4), SmallInt(1)]
    00000244: f9400299  ldr x25, [x20]
    00000248: 91002294  add x20, x20, #0x8
    0000024c: f840869e  ldr x30, [x20], #0x8
    00000250: d2925e0d  mov x13, #0x92f0 ; =37616
    00000254: f2bfd58d  movk x13, #0xfeac, lsl #16
    00000258: f2c000ed  movk x13, #0x7, lsl #32
    0000025c: f94001ae  ldr x14, [x13]
    00000260: aa1503e0  mov x0, x21
    00000264: aa0d03e1  mov x1, x13
    00000268: d61f01c0  br x14
# i_flush_stubs []
# kernels:fib/1
# i_func_label [SmallInt(8)]
# func_line [SmallInt(7)]
# i_func_info [SmallInt(8), Atom(1), Atom(12), SmallInt(1)]
    0000026c: d503201f  nop
# aligned_label [SmallInt(9), SmallInt(4)]
# i_breakpoint_trampoline []
    00000270: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    00000274: 710006d6  subs w22, w22, #0x1
    00000278: 5400008c  b.gt 0x288 <ltmp0+0x288>
    0000027c: 10000068  adr x8, 0x288 <ltmp0+0x288>
    00000280: f90026a8  str x8, [x21, #0x48]
    00000284: 1400023a  b 0xb6c <ltmp0+0xb6c>
# is_lt [Label(10), X(0), SmallInt(2)]
    00000288: d28005e9  mov x9, #0x2f ; =47
    0000028c: eb09033f  cmp x25, x9
    00000290: aa1903eb  mov x11, x25
    00000294: d28005e9  mov x9, #0x2f ; =47
    00000298: aa0903ec  mov x12, x9
    0000029c: f2400d68  ands x8, x11, #0xf
    000002a0: f1003d1f  cmp x8, #0xf
    000002a4: 540000e1  b.ne 0x2c0 <ltmp0+0x2c0>
    000002a8: f2400d88  ands x8, x12, #0xf
    000002ac: f1003d1f  cmp x8, #0xf
    000002b0: 54000081  b.ne 0x2c0 <ltmp0+0x2c0>
    000002b4: eb0c017f  cmp x11, x12
    000002b8: 5400034a  b.ge 0x320 <ltmp0+0x320>
    000002bc: 14000012  b 0x304 <ltmp0+0x304>
    000002c0: d28005e9  mov x9, #0x2f ; =47
    000002c4: d28002e8  mov x8, #0x17 ; =23
    000002c8: a902426f  stp x15, x16, [x19, #0x20]
    000002cc: aa1503e0  mov x0, x21
    000002d0: aa0803e1  mov x1, x8
    000002d4: aa1903e2  mov x2, x25
    000002d8: aa0903e3  mov x3, x9
    000002dc: d289cf91  mov x17, #0x4e7c ; =20092
    000002e0: f2a05e11  movk x17, #0x2f0, lsl #16
    000002e4: f2c00031  movk x17, #0x1, lsl #32
    000002e8: f90026be  str x30, [x21, #0x48]
    000002ec: d63f0220  blr x17
    000002f0: a942426f  ldp x15, x16, [x19, #0x20]
    000002f4: f94026be  ldr x30, [x21, #0x48]
    000002f8: f94016a9  ldr x9, [x21, #0x28]
    000002fc: b5004489  cbnz x9, 0xb8c <ltmp0+0xb8c>
    00000300: b4000100  cbz x0, 0x320 <ltmp0+0x320>
# return []
    00000304: f840869e  ldr x30, [x20], #0x8
    00000308: 710006d6  subs w22, w22, #0x1
    0000030c: f90026be  str x30, [x21, #0x48]
    00000310: 54000045  b.pl 0x318 <ltmp0+0x318>
    00000314: 14000216  b 0xb6c <ltmp0+0xb6c>
    00000318: aa1f03e0  mov x0, xzr
    0000031c: d65f03c0  ret
# label [SmallInt(10)]
# line [SmallInt(8)]
# i_minus [Label(0), SmallInt(1), X(0), SmallInt(1), X(1)]
    00000320: f1004320  subs x0, x25, #0x10
    00000324: 92400f28  and x8, x25, #0xf
    00000328: fa4f7900  ccmp x8, #0xf, #0x0, vc
    0000032c: 54000280  b.eq 0x37c <ltmp0+0x37c>
    00000330: aa1903ee  mov x14, x25
    00000334: d28003f1  mov x17, #0x1f ; =31
    00000338: d2800028  mov x8, #0x1 ; =1
    0000033c: b90022b6  str w22, [x21, #0x20]
    00000340: a902426f  stp x15, x16, [x19, #0x20]
    00000344: aa1503e0  mov x0, x21
    00000348: aa0803e1  mov x1, x8
    0000034c: aa0e03e2  mov x2, x14
    00000350: aa1103e3  mov x3, x17
    00000354: d2879491  mov x17, #0x3ca4 ; =15524
    00000358: f2a05e11  movk x17, #0x2f0, lsl #16
    0000035c: f2c00031  movk x17, #0x1, lsl #32
    00000360: f90026be  str x30, [x21, #0x48]
    00000364: d63f0220  blr x17
    00000368: b94022b6  ldr w22, [x21, #0x20]
    0000036c: a942426f  ldp x15, x16, [x19, #0x20]
    00000370: f94026be  ldr x30, [x21, #0x48]
    00000374: f94016a9  ldr x9, [x21, #0x28]
    00000378: b50040a9  cbnz x9, 0xb8c <ltmp0+0xb8c>
    0000037c: aa0003fa  mov x26, x0
# allocate [SmallInt(1), SmallInt(2)]
    00000380: 910062e8  add x8, x23, #0x18
    00000384: eb14011f  cmp x8, x20
    00000388: 54000269  b.ls 0x3d4 <ltmp0+0x3d4>
    0000038c: a90052b7  stp x23, x20, [x21]
    00000390: a9006a79  stp x25, x26, [x19]
    00000394: f90026be  str x30, [x21, #0x48]
    00000398: aa1503e0  mov x0, x21
    0000039c: aa1303e1  mov x1, x19
    000003a0: d2800022  mov x2, #0x1 ; =1
    000003a4: d2800043  mov x3, #0x2 ; =2
    000003a8: 2a1603e4  mov w4, w22
    000003ac: d2876691  mov x17, #0x3b34 ; =15156
    000003b0: f2a05e11  movk x17, #0x2f0, lsl #16
    000003b4: f2c00031  movk x17, #0x1, lsl #32
    000003b8: d63f0220  blr x17
    000003bc: a94052b7  ldp x23, x20, [x21]
    000003c0: a9406a79  ldp x25, x26, [x19]
    000003c4: 4b0002d6  sub w22, w22, w0
    000003c8: f94026be  ldr x30, [x21, #0x48]
    000003cc: f94016a9  ldr x9, [x21, #0x28]
    000003d0: b5003de9  cbnz x9, 0xb8c <ltmp0+0xb8c>
    000003d4: d1002294  sub x20, x20, #0x8
# i_move [X(0), Y(0)]
    000003d8: f9000299  str x25, [x20]
# i_move [X(1), X(0)]
    000003dc: aa1a03f9  mov x25, x26
# i_call [Label(9)]
    000003e0: 1000007e  adr x30, 0x3ec <ltmp0+0x3ec>
    000003e4: 14000001  b 0x3e8 <ltmp0+0x3e8>
    000003e8: 17ffffa2  b 0x270 <ltmp0+0x270>
# i_minus [Label(0), SmallInt(1), Y(0), SmallInt(2), X(1)]
    000003ec: f9400289  ldr x9, [x20]
    000003f0: f1008120  subs x0, x9, #0x20
    000003f4: 92400d28  and x8, x9, #0xf
    000003f8: fa4f7900  ccmp x8, #0xf, #0x0, vc
    000003fc: 54000280  b.eq 0x44c <ltmp0+0x44c>
    00000400: aa0903ee  mov x14, x9
    00000404: d28005f1  mov x17, #0x2f ; =47
    00000408: d2800028  mov x8, #0x1 ; =1
    0000040c: b90022b6  str w22, [x21, #0x20]
    00000410: a902426f  stp x15, x16, [x19, #0x20]
    00000414: aa1503e0  mov x0, x21
    00000418: aa0803e1  mov x1, x8
    0000041c: aa0e03e2  mov x2, x14
    00000420: aa1103e3  mov x3, x17
    00000424: d2879491  mov x17, #0x3ca4 ; =15524
    00000428: f2a05e11  movk x17, #0x2f0, lsl #16
    0000042c: f2c00031  movk x17, #0x1, lsl #32
    00000430: f90026be  str x30, [x21, #0x48]
    00000434: d63f0220  blr x17
    00000438: b94022b6  ldr w22, [x21, #0x20]
    0000043c: a942426f  ldp x15, x16, [x19, #0x20]
    00000440: f94026be  ldr x30, [x21, #0x48]
    00000444: f94016a9  ldr x9, [x21, #0x28]
    00000448: b5003a29  cbnz x9, 0xb8c <ltmp0+0xb8c>
    0000044c: aa0003fa  mov x26, x0
# i_move [X(0), Y(0)]
    00000450: f9000299  str x25, [x20]
# i_move [X(1), X(0)]
    00000454: aa1a03f9  mov x25, x26
# i_call [Label(9)]
    00000458: 1000007e  adr x30, 0x464 <ltmp0+0x464>
    0000045c: 14000001  b 0x460 <ltmp0+0x460>
    00000460: 17ffff84  b 0x270 <ltmp0+0x270>
# i_plus [Label(0), SmallInt(1), Y(0), X(0), X(0)]
    00000464: f9400289  ldr x9, [x20]
    00000468: aa0903ea  mov x10, x9
    0000046c: aa0903ee  mov x14, x9
    00000470: aa1903eb  mov x11, x25
    00000474: aa1903f1  mov x17, x25
    00000478: f2400d48  ands x8, x10, #0xf
    0000047c: f1003d1f  cmp x8, #0xf
    00000480: 540001e1  b.ne 0x4bc <ltmp0+0x4bc>
    00000484: f2400d68  ands x8, x11, #0xf
    00000488: f1003d1f  cmp x8, #0xf
    0000048c: 54000181  b.ne 0x4bc <ltmp0+0x4bc>
    00000490: 9344fd4a  asr x10, x10, #4
    00000494: 9344fd6b  asr x11, x11, #4
    00000498: 8b0b014c  add x12, x10, x11
    0000049c: d37ced8d  lsl x13, x12, #4
    000004a0: 9344fdad  asr x13, x13, #4
    000004a4: eb0d019f  cmp x12, x13
    000004a8: 540000a1  b.ne 0x4bc <ltmp0+0x4bc>
    000004ac: d37ced8c  lsl x12, x12, #4
    000004b0: b2400d8c  orr x12, x12, #0xf
    000004b4: aa0c03f9  mov x25, x12
    000004b8: 14000013  b 0x504 <ltmp0+0x504>
    000004bc: d2800008  mov x8, #0x0 ; =0
    000004c0: b90022b6  str w22, [x21, #0x20]
    000004c4: a902426f  stp x15, x16, [x19, #0x20]
    000004c8: aa1503e0  mov x0, x21
    000004cc: aa0803e1  mov x1, x8
    000004d0: aa0e03e2  mov x2, x14
    000004d4: aa1103e3  mov x3, x17
    000004d8: d2879491  mov x17, #0x3ca4 ; =15524
    000004dc: f2a05e11  movk x17, #0x2f0, lsl #16
    000004e0: f2c00031  movk x17, #0x1, lsl #32
    000004e4: f90026be  str x30, [x21, #0x48]
    000004e8: d63f0220  blr x17
    000004ec: b94022b6  ldr w22, [x21, #0x20]
    000004f0: a942426f  ldp x15, x16, [x19, #0x20]
    000004f4: f94026be  ldr x30, [x21, #0x48]
    000004f8: f94016a9  ldr x9, [x21, #0x28]
    000004fc: b5003489  cbnz x9, 0xb8c <ltmp0+0xb8c>
    00000500: aa0003f9  mov x25, x0
# deallocate [SmallInt(1)]
    00000504: 91002294  add x20, x20, #0x8
# return []
    00000508: f840869e  ldr x30, [x20], #0x8
    0000050c: 710006d6  subs w22, w22, #0x1
    00000510: f90026be  str x30, [x21, #0x48]
    00000514: 54000045  b.pl 0x51c <ltmp0+0x51c>
    00000518: 14000195  b 0xb6c <ltmp0+0xb6c>
    0000051c: aa1f03e0  mov x0, xzr
    00000520: d65f03c0  ret
# i_flush_stubs []
# kernels:tuple/1
# i_func_label [SmallInt(11)]
# func_line [SmallInt(9)]
# i_func_info [SmallInt(11), Atom(1), Atom(13), SmallInt(1)]
    00000524: d503201f  nop
# aligned_label [SmallInt(12), SmallInt(4)]
# i_breakpoint_trampoline []
    00000528: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    0000052c: 710006d6  subs w22, w22, #0x1
    00000530: 5400008c  b.gt 0x540 <ltmp0+0x540>
    00000534: 10000068  adr x8, 0x540 <ltmp0+0x540>
    00000538: f90026a8  str x8, [x21, #0x48]
    0000053c: 1400018c  b 0xb6c <ltmp0+0xb6c>
# test_heap [SmallInt(4), SmallInt(1)]
    00000540: 9100c2e8  add x8, x23, #0x30
    00000544: eb14011f  cmp x8, x20
    00000548: 54000269  b.ls 0x594 <ltmp0+0x594>
    0000054c: a90052b7  stp x23, x20, [x21]
    00000550: f9000279  str x25, [x19]
    00000554: f90026be  str x30, [x21, #0x48]
    00000558: aa1503e0  mov x0, x21
    0000055c: aa1303e1  mov x1, x19
    00000560: d2800082  mov x2, #0x4 ; =4
    00000564: d2800023  mov x3, #0x1 ; =1
    00000568: 2a1603e4  mov w4, w22
    0000056c: d2876691  mov x17, #0x3b34 ; =15156
    00000570: f2a05e11  movk x17, #0x2f0, lsl #16
    00000574: f2c00031  movk x17, #0x1, lsl #32
    00000578: d63f0220  blr x17
    0000057c: a94052b7  ldp x23, x20, [x21]
    00000580: f9400279  ldr x25, [x19]
    00000584: 4b0002d6  sub w22, w22, w0
    00000588: f94026be  ldr x30, [x21, #0x48]
    0000058c: f94016a9  ldr x9, [x21, #0x28]
    00000590: b5002fe9  cbnz x9, 0xb8c <ltmp0+0xb8c>
# put_tuple2 [X(1), List([SmallInt(0), SmallInt(0), SmallInt(0)])]
    00000594: d280180c  mov x12, #0xc0 ; =192
    00000598: f80086ec  str x12, [x23], #0x8
    0000059c: d28001e9  mov x9, #0xf ; =15
    000005a0: aa0903ea  mov x10, x9
    000005a4: d28001e9  mov x9, #0xf ; =15
    000005a8: aa0903eb  mov x11, x9
    000005ac: a8812eea  stp x10, x11, [x23], #0x10
    000005b0: d28001e9  mov x9, #0xf ; =15
    000005b4: aa0903ea  mov x10, x9
    000005b8: f80086ea  str x10, [x23], #0x8
    000005bc: d1007aec  sub x12, x23, #0x1e
    000005c0: aa0c03fa  mov x26, x12
# i_move [SmallInt(0), X(2)]
    000005c4: d28001fb  mov x27, #0xf ; =15
# i_call_only [Label(14)]
    000005c8: f840869e  ldr x30, [x20], #0x8
    000005cc: 710006d6  subs w22, w22, #0x1
    000005d0: 540000a5  b.pl 0x5e4 <ltmp0+0x5e4>
    000005d4: 10000088  adr x8, 0x5e4 <ltmp0+0x5e4>
    000005d8: f90026a8  str x8, [x21, #0x48]
    000005dc: 14000164  b 0xb6c <ltmp0+0xb6c>
# i_flush_stubs []
# kernels:tuple_loop/3
# i_func_label [SmallInt(13)]
# func_line [SmallInt(10)]
# i_func_info [SmallInt(13), Atom(1), Atom(14), SmallInt(3)]
    000005e0: d503201f  nop
# aligned_label [SmallInt(14), SmallInt(4)]
# i_breakpoint_trampoline []
    000005e4: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    000005e8: 710006d6  subs w22, w22, #0x1
    000005ec: 5400008c  b.gt 0x5fc <ltmp0+0x5fc>
    000005f0: 10000068  adr x8, 0x5fc <ltmp0+0x5fc>
    000005f4: f90026a8  str x8, [x21, #0x48]
    000005f8: 1400015d  b 0xb6c <ltmp0+0xb6c>
# is_eq_exact [Label(15), X(0), SmallInt(0)]
    000005fc: f1003f3f  cmp x25, #0xf
    00000600: 54000121  b.ne 0x624 <ltmp0+0x624>
# i_move [X(2), X(0)]
    00000604: aa1b03f9  mov x25, x27
# return []
    00000608: f840869e  ldr x30, [x20], #0x8
    0000060c: 710006d6  subs w22, w22, #0x1
    00000610: f90026be  str x30, [x21, #0x48]
    00000614: 54000045  b.pl 0x61c <ltmp0+0x61c>
    00000618: 14000155  b 0xb6c <ltmp0+0xb6c>
    0000061c: aa1f03e0  mov x0, xzr
    00000620: d65f03c0  ret
# label [SmallInt(15)]
# test_heap [SmallInt(4), SmallInt(3)]
    00000624: 9100c2e8  add x8, x23, #0x30
    00000628: eb14011f  cmp x8, x20
    0000062c: 540002a9  b.ls 0x680 <ltmp0+0x680>
    00000630: a90052b7  stp x23, x20, [x21]
    00000634: a9006a79  stp x25, x26, [x19]
    00000638: f9000a7b  str x27, [x19, #0x10]
    0000063c: f90026be  str x30, [x21, #0x48]
    00000640: aa1503e0  mov x0, x21
    00000644: aa1303e1  mov x1, x19
    00000648: d2800082  mov x2, #0x4 ; =4
    0000064c: d2800063  mov x3, #0x3 ; =3
    00000650: 2a1603e4  mov w4, w22
    00000654: d2876691  mov x17, #0x3b34 ; =15156
    00000658: f2a05e11  movk x17, #0x2f0, lsl #16
    0000065c: f2c00031  movk x17, #0x1, lsl #32
    00000660: d63f0220  blr x17
    00000664: a94052b7  ldp x23, x20, [x21]
    00000668: a9406a79  ldp x25, x26, [x19]
    0000066c: f9400a7b  ldr x27, [x19, #0x10]
    00000670: 4b0002d6  sub w22, w22, w0
    00000674: f94026be  ldr x30, [x21, #0x48]
    00000678: f94016a9  ldr x9, [x21, #0x28]
    0000067c: b5002889  cbnz x9, 0xb8c <ltmp0+0xb8c>
# update_record_in_place [SmallInt(3), X(1), X(1), SmallInt(2), SmallInt(2), X(0)]
    00000680: 927df348  and x8, x26, #0xfffffffffffffff8
    00000684: f9403aac  ldr x12, [x21, #0x70]
    00000688: eb17011f  cmp x8, x23
    0000068c: 54000122  b.hs 0x6b0 <ltmp0+0x6b0>
    00000690: eb0c011f  cmp x8, x12
    00000694: 540000e2  b.hs 0x6b0 <ltmp0+0x6b0>
    00000698: d280008d  mov x13, #0x4 ; =4
    0000069c: f840850a  ldr x10, [x8], #0x8
    000006a0: f80086ea  str x10, [x23], #0x8
    000006a4: f10005ad  subs x13, x13, #0x1
    000006a8: 54ffffa1  b.ne 0x69c <ltmp0+0x69c>
    000006ac: d10082e8  sub x8, x23, #0x20
    000006b0: aa1903ea  mov x10, x25
    000006b4: 91004109  add x9, x8, #0x10
    000006b8: f900012a  str x10, [x9]
    000006bc: 9100090c  add x12, x8, #0x2
    000006c0: aa0c03fa  mov x26, x12
# line [SmallInt(11)]
# i_minus [Label(0), SmallInt(3), X(0), SmallInt(1), X(0)]
    000006c4: f1004320  subs x0, x25, #0x10
    000006c8: 92400f28  and x8, x25, #0xf
    000006cc: fa4f7900  ccmp x8, #0xf, #0x0, vc
    000006d0: 54000280  b.eq 0x720 <ltmp0+0x720>
    000006d4: aa1903ee  mov x14, x25
    000006d8: d28003f1  mov x17, #0x1f ; =31
    000006dc: d2800028  mov x8, #0x1 ; =1
    000006e0: b90022b6  str w22, [x21, #0x20]
    000006e4: a902426f  stp x15, x16, [x19, #0x20]
    000006e8: aa1503e0  mov x0, x21
    000006ec: aa0803e1  mov x1, x8
    000006f0: aa0e03e2  mov x2, x14
    000006f4: aa1103e3  mov x3, x17
    000006f8: d2879491  mov x17, #0x3ca4 ; =15524
    000006fc: f2a05e11  movk x17, #0x2f0, lsl #16
    00000700: f2c00031  movk x17, #0x1, lsl #32
    00000704: f90026be  str x30, [x21, #0x48]
    00000708: d63f0220  blr x17
    0000070c: b94022b6  ldr w22, [x21, #0x20]
    00000710: a942426f  ldp x15, x16, [x19, #0x20]
    00000714: f94026be  ldr x30, [x21, #0x48]
    00000718: f94016a9  ldr x9, [x21, #0x28]
    0000071c: b5002389  cbnz x9, 0xb8c <ltmp0+0xb8c>
    00000720: aa0003f9  mov x25, x0
# load_tuple_ptr [X(1)]
    00000724: 927df348  and x8, x26, #0xfffffffffffffff8
    00000728: aa0803fa  mov x26, x8
# i_get_tuple_element [X(1), SmallInt(1), X(3)]
    0000072c: 927df348  and x8, x26, #0xfffffffffffffff8
    00000730: f940091c  ldr x28, [x8, #0x10]
    00000734: aa1c03fc  mov x28, x28
# i_plus [Label(0), SmallInt(4), X(2), X(3), X(2)]
    00000738: aa1b03ea  mov x10, x27
    0000073c: aa1b03ee  mov x14, x27
    00000740: aa1c03eb  mov x11, x28
    00000744: aa1c03f1  mov x17, x28
    00000748: f2400d48  ands x8, x10, #0xf
    0000074c: f1003d1f  cmp x8, #0xf
    00000750: 540001e1  b.ne 0x78c <ltmp0+0x78c>
    00000754: f2400d68  ands x8, x11, #0xf
    00000758: f1003d1f  cmp x8, #0xf
    0000075c: 54000181  b.ne 0x78c <ltmp0+0x78c>
    00000760: 9344fd4a  asr x10, x10, #4
    00000764: 9344fd6b  asr x11, x11, #4
    00000768: 8b0b014c  add x12, x10, x11
    0000076c: d37ced8d  lsl x13, x12, #4
    00000770: 9344fdad  asr x13, x13, #4
    00000774: eb0d019f  cmp x12, x13
    00000778: 540000a1  b.ne 0x78c <ltmp0+0x78c>
    0000077c: d37ced8c  lsl x12, x12, #4
    00000780: b2400d8c  orr x12, x12, #0xf
    00000784: aa0c03fb  mov x27, x12
    00000788: 14000013  b 0x7d4 <ltmp0+0x7d4>
    0000078c: d2800008  mov x8, #0x0 ; =0
    00000790: b90022b6  str w22, [x21, #0x20]
    00000794: a902426f  stp x15, x16, [x19, #0x20]
    00000798: aa1503e0  mov x0, x21
    0000079c: aa0803e1  mov x1, x8
    000007a0: aa0e03e2  mov x2, x14
    000007a4: aa1103e3  mov x3, x17
    000007a8: d2879491  mov x17, #0x3ca4 ; =15524
    000007ac: f2a05e11  movk x17, #0x2f0, lsl #16
    000007b0: f2c00031  movk x17, #0x1, lsl #32
    000007b4: f90026be  str x30, [x21, #0x48]
    000007b8: d63f0220  blr x17
    000007bc: b94022b6  ldr w22, [x21, #0x20]
    000007c0: a942426f  ldp x15, x16, [x19, #0x20]
    000007c4: f94026be  ldr x30, [x21, #0x48]
    000007c8: f94016a9  ldr x9, [x21, #0x28]
    000007cc: b5001e09  cbnz x9, 0xb8c <ltmp0+0xb8c>
    000007d0: aa0003fb  mov x27, x0
# i_call_only [Label(14)]
    000007d4: f840869e  ldr x30, [x20], #0x8
    000007d8: 710006d6  subs w22, w22, #0x1
    000007dc: 54fff045  b.pl 0x5e4 <ltmp0+0x5e4>
    000007e0: 10fff028  adr x8, 0x5e4 <ltmp0+0x5e4>
    000007e4: f90026a8  str x8, [x21, #0x48]
    000007e8: 140000e1  b 0xb6c <ltmp0+0xb6c>
# i_flush_stubs []
# kernels:module_info/0
# i_func_label [SmallInt(23)]
# func_line [SmallInt(0)]
# i_func_info [SmallInt(23), Atom(1), Atom(22), SmallInt(0)]
    000007ec: d503201f  nop
# aligned_label [SmallInt(24), SmallInt(4)]
# i_breakpoint_trampoline []
    000007f0: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    000007f4: 710006d6  subs w22, w22, #0x1
    000007f8: 5400008c  b.gt 0x808 <ltmp0+0x808>
    000007fc: 10000068  adr x8, 0x808 <ltmp0+0x808>
    00000800: f90026a8  str x8, [x21, #0x48]
    00000804: 140000da  b 0xb6c <ltmp0+0xb6c>
# i_move [Atom(1), X(0)]
    00000808: d287d979  mov x25, #0x3ecb ; =16075
    0000080c: f2a00139  movk x25, #0x9, lsl #16
# allocate [SmallInt(0), SmallInt(1)]
    00000810: 910042e8  add x8, x23, #0x10
    00000814: eb14011f  cmp x8, x20
    00000818: 54000269  b.ls 0x864 <ltmp0+0x864>
    0000081c: a90052b7  stp x23, x20, [x21]
    00000820: f9000279  str x25, [x19]
    00000824: f90026be  str x30, [x21, #0x48]
    00000828: aa1503e0  mov x0, x21
    0000082c: aa1303e1  mov x1, x19
    00000830: d2800002  mov x2, #0x0 ; =0
    00000834: d2800023  mov x3, #0x1 ; =1
    00000838: 2a1603e4  mov w4, w22
    0000083c: d2876691  mov x17, #0x3b34 ; =15156
    00000840: f2a05e11  movk x17, #0x2f0, lsl #16
    00000844: f2c00031  movk x17, #0x1, lsl #32
    00000848: d63f0220  blr x17
    0000084c: a94052b7  ldp x23, x20, [x21]
    00000850: f9400279  ldr x25, [x19]
    00000854: 4b0002d6  sub w22, w22, w0
    00000858: f94026be  ldr x30, [x21, #0x48]
    0000085c: f94016a9  ldr x9, [x21, #0x28]
    00000860: b5001969  cbnz x9, 0xb8c <ltmp0+0xb8c>
# call_light_bif [SmallInt(6), SmallInt(6)]
    00000864: 710006d6  subs w22, w22, #0x1
    00000868: 5400008c  b.gt 0x878 <ltmp0+0x878>
    0000086c: 10000068  adr x8, 0x878 <ltmp0+0x878>
    00000870: f90026a8  str x8, [x21, #0x48]
    00000874: 140000be  b 0xb6c <ltmp0+0xb6c>
    00000878: d292660d  mov x13, #0x9330 ; =37680
    0000087c: f2bfd58d  movk x13, #0xfeac, lsl #16
    00000880: f2c000ed  movk x13, #0x7, lsl #32
    00000884: a90052b7  stp x23, x20, [x21]
    00000888: b90022b6  str w22, [x21, #0x20]
    0000088c: a9006a79  stp x25, x26, [x19]
    00000890: a901727b  stp x27, x28, [x19, #0x10]
    00000894: a902426f  stp x15, x16, [x19, #0x20]
    00000898: aa1503e0  mov x0, x21
    0000089c: aa0d03e1  mov x1, x13
    000008a0: d2801091  mov x17, #0x84 ; =132
    000008a4: f2a07291  movk x17, #0x394, lsl #16
    000008a8: f2c00031  movk x17, #0x1, lsl #32
    000008ac: f90026be  str x30, [x21, #0x48]
    000008b0: d63f0220  blr x17
    000008b4: a94052b7  ldp x23, x20, [x21]
    000008b8: b94022b6  ldr w22, [x21, #0x20]
    000008bc: a9406a79  ldp x25, x26, [x19]
    000008c0: a941727b  ldp x27, x28, [x19, #0x10]
    000008c4: a942426f  ldp x15, x16, [x19, #0x20]
    000008c8: f94026be  ldr x30, [x21, #0x48]
    000008cc: f94016a9  ldr x9, [x21, #0x28]
    000008d0: b50015e9  cbnz x9, 0xb8c <ltmp0+0xb8c>
    000008d4: aa0003f9  mov x25, x0
# deallocate [SmallInt(0)]
# return []
    000008d8: f840869e  ldr x30, [x20], #0x8
    000008dc: 710006d6  subs w22, w22, #0x1
    000008e0: f90026be  str x30, [x21, #0x48]
    000008e4: 54000045  b.pl 0x8ec <ltmp0+0x8ec>
    000008e8: 140000a1  b 0xb6c <ltmp0+0xb6c>
    000008ec: aa1f03e0  mov x0, xzr
    000008f0: d65f03c0  ret
# i_flush_stubs []
# kernels:module_info/1
# i_func_label [SmallInt(25)]
# func_line [SmallInt(0)]
# i_func_info [SmallInt(25), Atom(1), Atom(22), SmallInt(1)]
    000008f4: d503201f  nop
# aligned_label [SmallInt(26), SmallInt(4)]
# i_breakpoint_trampoline []
    000008f8: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    000008fc: 710006d6  subs w22, w22, #0x1
    00000900: 5400008c  b.gt 0x910 <ltmp0+0x910>
    00000904: 10000068  adr x8, 0x910 <ltmp0+0x910>
    00000908: f90026a8  str x8, [x21, #0x48]
    0000090c: 14000098  b 0xb6c <ltmp0+0xb6c>
# i_move [X(0), X(1)]
    00000910: aa1903fa  mov x26, x25
# i_move [Atom(1), X(0)]
    00000914: d287d979  mov x25, #0x3ecb ; =16075
    00000918: f2a00139  movk x25, #0x9, lsl #16
# allocate [SmallInt(0), SmallInt(2)]
    0000091c: 910042e8  add x8, x23, #0x10
    00000920: eb14011f  cmp x8, x20
    00000924: 54000269  b.ls 0x970 <ltmp0+0x970>
    00000928: a90052b7  stp x23, x20, [x21]
    0000092c: a9006a79  stp x25, x26, [x19]
    00000930: f90026be  str x30, [x21, #0x48]
    00000934: aa1503e0  mov x0, x21
    00000938: aa1303e1  mov x1, x19
    0000093c: d2800002  mov x2, #0x0 ; =0
    00000940: d2800043  mov x3, #0x2 ; =2
    00000944: 2a1603e4  mov w4, w22
    00000948: d2876691  mov x17, #0x3b34 ; =15156
    0000094c: f2a05e11  movk x17, #0x2f0, lsl #16
    00000950: f2c00031  movk x17, #0x1, lsl #32
    00000954: d63f0220  blr x17
    00000958: a94052b7  ldp x23, x20, [x21]
    0000095c: a9406a79  ldp x25, x26, [x19]
    00000960: 4b0002d6  sub w22, w22, w0
    00000964: f94026be  ldr x30, [x21, #0x48]
    00000968: f94016a9  ldr x9, [x21, #0x28]
    0000096c: b5001109  cbnz x9, 0xb8c <ltmp0+0xb8c>
# call_light_bif [SmallInt(7), SmallInt(7)]
    00000970: 710006d6  subs w22, w22, #0x1
    00000974: 5400008c  b.gt 0x984 <ltmp0+0x984>
    00000978: 10000068  adr x8, 0x984 <ltmp0+0x984>
    0000097c: f90026a8  str x8, [x21, #0x48]
    00000980: 1400007b  b 0xb6c <ltmp0+0xb6c>
    00000984: d2926a0d  mov x13, #0x9350 ; =37712
    00000988: f2bfd58d  movk x13, #0xfeac, lsl #16
    0000098c: f2c000ed  movk x13, #0x7, lsl #32
    00000990: a90052b7  stp x23, x20, [x21]
    00000994: b90022b6  str w22, [x21, #0x20]
    00000998: a9006a79  stp x25, x26, [x19]
    0000099c: a901727b  stp x27, x28, [x19, #0x10]
    000009a0: a902426f  stp x15, x16, [x19, #0x20]
    000009a4: aa1503e0  mov x0, x21
    000009a8: aa0d03e1  mov x1, x13
    000009ac: d2801091  mov x17, #0x84 ; =132
    000009b0: f2a07291  movk x17, #0x394, lsl #16
    000009b4: f2c00031  movk x17, #0x1, lsl #32
    000009b8: f90026be  str x30, [x21, #0x48]
    000009bc: d63f0220  blr x17
    000009c0: a94052b7  ldp x23, x20, [x21]
    000009c4: b94022b6  ldr w22, [x21, #0x20]
    000009c8: a9406a79  ldp x25, x26, [x19]
    000009cc: a941727b  ldp x27, x28, [x19, #0x10]
    000009d0: a942426f  ldp x15, x16, [x19, #0x20]
    000009d4: f94026be  ldr x30, [x21, #0x48]
    000009d8: f94016a9  ldr x9, [x21, #0x28]
    000009dc: b5000d89  cbnz x9, 0xb8c <ltmp0+0xb8c>
    000009e0: aa0003f9  mov x25, x0
# deallocate [SmallInt(0)]
# return []
    000009e4: f840869e  ldr x30, [x20], #0x8
    000009e8: 710006d6  subs w22, w22, #0x1
    000009ec: f90026be  str x30, [x21, #0x48]
    000009f0: 54000045  b.pl 0x9f8 <ltmp0+0x9f8>
    000009f4: 1400005e  b 0xb6c <ltmp0+0xb6c>
    000009f8: aa1f03e0  mov x0, xzr
    000009fc: d65f03c0  ret
# i_flush_stubs []
# kernels:-list/1-fun-0-/1
# i_func_label [SmallInt(27)]
# func_line [SmallInt(5)]
# i_func_info [SmallInt(27), Atom(1), Atom(24), SmallInt(1)]
    00000a00: d503201f  nop
# aligned_label [SmallInt(28), SmallInt(4)]
# i_breakpoint_trampoline []
    00000a04: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    00000a08: 710006d6  subs w22, w22, #0x1
    00000a0c: 5400008c  b.gt 0xa1c <ltmp0+0xa1c>
    00000a10: 10000068  adr x8, 0xa1c <ltmp0+0xa1c>
    00000a14: f90026a8  str x8, [x21, #0x48]
    00000a18: 14000055  b 0xb6c <ltmp0+0xb6c>
# i_plus [Label(0), SmallInt(1), X(0), SmallInt(1), X(0)]
    00000a1c: b1004320  adds x0, x25, #0x10
    00000a20: 92400f28  and x8, x25, #0xf
    00000a24: fa4f7900  ccmp x8, #0xf, #0x0, vc
    00000a28: 54000280  b.eq 0xa78 <ltmp0+0xa78>
    00000a2c: aa1903ee  mov x14, x25
    00000a30: d28003f1  mov x17, #0x1f ; =31
    00000a34: d2800008  mov x8, #0x0 ; =0
    00000a38: b90022b6  str w22, [x21, #0x20]
    00000a3c: a902426f  stp x15, x16, [x19, #0x20]
    00000a40: aa1503e0  mov x0, x21
    00000a44: aa0803e1  mov x1, x8
    00000a48: aa0e03e2  mov x2, x14
    00000a4c: aa1103e3  mov x3, x17
    00000a50: d2879491  mov x17, #0x3ca4 ; =15524
    00000a54: f2a05e11  movk x17, #0x2f0, lsl #16
    00000a58: f2c00031  movk x17, #0x1, lsl #32
    00000a5c: f90026be  str x30, [x21, #0x48]
    00000a60: d63f0220  blr x17
    00000a64: b94022b6  ldr w22, [x21, #0x20]
    00000a68: a942426f  ldp x15, x16, [x19, #0x20]
    00000a6c: f94026be  ldr x30, [x21, #0x48]
    00000a70: f94016a9  ldr x9, [x21, #0x28]
    00000a74: b50008c9  cbnz x9, 0xb8c <ltmp0+0xb8c>
    00000a78: aa0003f9  mov x25, x0
# return []
    00000a7c: f840869e  ldr x30, [x20], #0x8
    00000a80: 710006d6  subs w22, w22, #0x1
    00000a84: f90026be  str x30, [x21, #0x48]
    00000a88: 54000045  b.pl 0xa90 <ltmp0+0xa90>
    00000a8c: 14000038  b 0xb6c <ltmp0+0xb6c>
    00000a90: aa1f03e0  mov x0, xzr
    00000a94: d65f03c0  ret
# i_flush_stubs []
# kernels:-list/1-fun-1-/2
# i_func_label [SmallInt(29)]
# func_line [SmallInt(6)]
# i_func_info [SmallInt(29), Atom(1), Atom(25), SmallInt(2)]
    00000a98: d503201f  nop
# aligned_label [SmallInt(30), SmallInt(4)]
# i_breakpoint_trampoline []
    00000a9c: f81f8e9e  str x30, [x20, #-0x8]!
# i_test_yield []
    00000aa0: 710006d6  subs w22, w22, #0x1
    00000aa4: 5400008c  b.gt 0xab4 <ltmp0+0xab4>
    00000aa8: 10000068  adr x8, 0xab4 <ltmp0+0xab4>
    00000aac: f90026a8  str x8, [x21, #0x48]
    00000ab0: 1400002f  b 0xb6c <ltmp0+0xb6c>
# i_plus [Label(0), SmallInt(2), X(0), X(1), X(0)]
    00000ab4: aa1903ea  mov x10, x25
    00000ab8: aa1903ee  mov x14, x25
    00000abc: aa1a03eb  mov x11, x26
    00000ac0: aa1a03f1  mov x17, x26
    00000ac4: f2400d48  ands x8, x10, #0xf
    00000ac8: f1003d1f  cmp x8, #0xf
    00000acc: 540001e1  b.ne 0xb08 <ltmp0+0xb08>
    00000ad0: f2400d68  ands x8, x11, #0xf
    00000ad4: f1003d1f  cmp x8, #0xf
    00000ad8: 54000181  b.ne 0xb08 <ltmp0+0xb08>
    00000adc: 9344fd4a  asr x10, x10, #4
    00000ae0: 9344fd6b  asr x11, x11, #4
    00000ae4: 8b0b014c  add x12, x10, x11
    00000ae8: d37ced8d  lsl x13, x12, #4
    00000aec: 9344fdad  asr x13, x13, #4
    00000af0: eb0d019f  cmp x12, x13
    00000af4: 540000a1  b.ne 0xb08 <ltmp0+0xb08>
    00000af8: d37ced8c  lsl x12, x12, #4
    00000afc: b2400d8c  orr x12, x12, #0xf
    00000b00: aa0c03f9  mov x25, x12
    00000b04: 14000013  b 0xb50 <ltmp0+0xb50>
    00000b08: d2800008  mov x8, #0x0 ; =0
    00000b0c: b90022b6  str w22, [x21, #0x20]
    00000b10: a902426f  stp x15, x16, [x19, #0x20]
    00000b14: aa1503e0  mov x0, x21
    00000b18: aa0803e1  mov x1, x8
    00000b1c: aa0e03e2  mov x2, x14
    00000b20: aa1103e3  mov x3, x17
    00000b24: d2879491  mov x17, #0x3ca4 ; =15524
    00000b28: f2a05e11  movk x17, #0x2f0, lsl #16
    00000b2c: f2c00031  movk x17, #0x1, lsl #32
    00000b30: f90026be  str x30, [x21, #0x48]
    00000b34: d63f0220  blr x17
    00000b38: b94022b6  ldr w22, [x21, #0x20]
    00000b3c: a942426f  ldp x15, x16, [x19, #0x20]
    00000b40: f94026be  ldr x30, [x21, #0x48]
    00000b44: f94016a9  ldr x9, [x21, #0x28]
    00000b48: b5000229  cbnz x9, 0xb8c <ltmp0+0xb8c>
    00000b4c: aa0003f9  mov x25, x0
# return []
    00000b50: f840869e  ldr x30, [x20], #0x8
    00000b54: 710006d6  subs w22, w22, #0x1
    00000b58: f90026be  str x30, [x21, #0x48]
    00000b5c: 54000045  b.pl 0xb64 <ltmp0+0xb64>
    00000b60: 14000003  b 0xb6c <ltmp0+0xb6c>
    00000b64: aa1f03e0  mov x0, xzr
    00000b68: d65f03c0  ret
# int_code_end []
# assembler epilogue and unassociated code
    00000b6c: a90052b7  stp x23, x20, [x21]
    00000b70: b90022b6  str w22, [x21, #0x20]
    00000b74: a9006a79  stp x25, x26, [x19]
    00000b78: a901727b  stp x27, x28, [x19, #0x10]
    00000b7c: a902426f  stp x15, x16, [x19, #0x20]
    00000b80: d2800020  mov x0, #0x1 ; =1
    00000b84: f960127e  ldr x30, [x19, #0x4020]
    00000b88: d65f03c0  ret
    00000b8c: aa1f03e0  mov x0, xzr
    00000b90: f960127e  ldr x30, [x19, #0x4020]
    00000b94: d61f03c0  br x30
