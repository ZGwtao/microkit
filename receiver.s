
tmp_build/receiver.elf:	file format elf64-littleaarch64

Disassembly of section .text:

0000000000200000 <_text>:
  200000: 14000998     	b	0x202660 <main>
		...

0000000000200010 <init>:
  200010: a9be7bfd     	stp	x29, x30, [sp, #-32]!
  200014: d2a00400     	mov	x0, #2097152
  200018: d0000001     	adrp	x1, 0x202000 <init+0x10>
  20001c: 911fc021     	add	x1, x1, #2032
  200020: 910003fd     	mov	x29, sp
  200024: f9400000     	ldr	x0, [x0]
  200028: 9400082e     	bl	0x2020e0 <putvar>
  20002c: d0000000     	adrp	x0, 0x202000 <init+0x24>
  200030: 91200000     	add	x0, x0, #2048
  200034: 9400090f     	bl	0x202470 <microkit_dbg_puts>
  200038: d297dde2     	mov	x2, #48879
  20003c: f2bbd5a2     	movk	x2, #57005, lsl #16
  200040: 910063e0     	add	x0, sp, #24
  200044: d0000001     	adrp	x1, 0x202000 <init+0x3c>
  200048: 91208021     	add	x1, x1, #2080
  20004c: f9000fe2     	str	x2, [sp, #24]
  200050: 94000824     	bl	0x2020e0 <putvar>
  200054: 128008e0     	mov	w0, #-72
  200058: d0000001     	adrp	x1, 0x202000 <init+0x50>
  20005c: 9120a021     	add	x1, x1, #2088
  200060: f2c01fe0     	movk	x0, #255, lsl #32
  200064: f9400000     	ldr	x0, [x0]
  200068: 9400081e     	bl	0x2020e0 <putvar>
  20006c: d0000000     	adrp	x0, 0x202000 <init+0x64>
  200070: 9120c000     	add	x0, x0, #2096
  200074: 940008ff     	bl	0x202470 <microkit_dbg_puts>
  200078: a8c27bfd     	ldp	x29, x30, [sp], #32
  20007c: d65f03c0     	ret

0000000000200080 <notified>:
  200080: a9be7bfd     	stp	x29, x30, [sp, #-32]!
  200084: 910003fd     	mov	x29, sp
  200088: f9000bf3     	str	x19, [sp, #16]
  20008c: 2a0003f3     	mov	w19, w0
  200090: d0000000     	adrp	x0, 0x202000 <notified+0x18>
  200094: 91214000     	add	x0, x0, #2128
  200098: 940008f6     	bl	0x202470 <microkit_dbg_puts>
  20009c: 2a1303e0     	mov	w0, w19
  2000a0: 940000b8     	bl	0x200380 <putdec>
  2000a4: f9400bf3     	ldr	x19, [sp, #16]
  2000a8: d0000000     	adrp	x0, 0x202000 <notified+0x30>
  2000ac: 912ce000     	add	x0, x0, #2872
  2000b0: a8c27bfd     	ldp	x29, x30, [sp], #32
  2000b4: 140008ef     	b	0x202470 <microkit_dbg_puts>
		...

00000000002000c0 <puthex>:
  2000c0: a9bc7bfd     	stp	x29, x30, [sp, #-64]!
  2000c4: 910003fd     	mov	x29, sp
  2000c8: f9000bf3     	str	x19, [sp, #16]
  2000cc: 3900e3ff     	strb	wzr, [sp, #56]
  2000d0: b50001a0     	cbnz	x0, 0x200104 <puthex+0x44>
  2000d4: 52800600     	mov	w0, #48
  2000d8: d28001f3     	mov	x19, #15
  2000dc: 3900dfe0     	strb	w0, [sp, #55]
  2000e0: d0000000     	adrp	x0, 0x202000 <puthex+0x28>
  2000e4: 91220000     	add	x0, x0, #2176
  2000e8: 940008e2     	bl	0x202470 <microkit_dbg_puts>
  2000ec: 9100a3e0     	add	x0, sp, #40
  2000f0: 8b130000     	add	x0, x0, x19
  2000f4: 940008df     	bl	0x202470 <microkit_dbg_puts>
  2000f8: f9400bf3     	ldr	x19, [sp, #16]
  2000fc: a8c47bfd     	ldp	x29, x30, [sp], #64
  200100: d65f03c0     	ret
  200104: 12000c01     	and	w1, w0, #0xf
  200108: d344fc02     	lsr	x2, x0, #4
  20010c: 7100283f     	cmp	w1, #10
  200110: 11015c23     	add	w3, w1, #87
  200114: 1100c021     	add	w1, w1, #48
  200118: 1a833021     	csel	w1, w1, w3, lo
  20011c: 3900dfe1     	strb	w1, [sp, #55]
  200120: b4000f02     	cbz	x2, 0x200300 <puthex+0x240>
  200124: 12000c41     	and	w1, w2, #0xf
  200128: d348fc02     	lsr	x2, x0, #8
  20012c: 7100283f     	cmp	w1, #10
  200130: 11015c23     	add	w3, w1, #87
  200134: 1100c021     	add	w1, w1, #48
  200138: 1a833021     	csel	w1, w1, w3, lo
  20013c: 3900dbe1     	strb	w1, [sp, #54]
  200140: b4000e82     	cbz	x2, 0x200310 <puthex+0x250>
  200144: 12000c41     	and	w1, w2, #0xf
  200148: d34cfc02     	lsr	x2, x0, #12
  20014c: 7100283f     	cmp	w1, #10
  200150: 11015c23     	add	w3, w1, #87
  200154: 1100c021     	add	w1, w1, #48
  200158: 1a833021     	csel	w1, w1, w3, lo
  20015c: 3900d7e1     	strb	w1, [sp, #53]
  200160: b4000dc2     	cbz	x2, 0x200318 <puthex+0x258>
  200164: 12000c41     	and	w1, w2, #0xf
  200168: d350fc02     	lsr	x2, x0, #16
  20016c: 7100283f     	cmp	w1, #10
  200170: 11015c23     	add	w3, w1, #87
  200174: 1100c021     	add	w1, w1, #48
  200178: 1a833021     	csel	w1, w1, w3, lo
  20017c: 3900d3e1     	strb	w1, [sp, #52]
  200180: b4000d02     	cbz	x2, 0x200320 <puthex+0x260>
  200184: 12000c41     	and	w1, w2, #0xf
  200188: d354fc02     	lsr	x2, x0, #20
  20018c: 7100283f     	cmp	w1, #10
  200190: 11015c23     	add	w3, w1, #87
  200194: 1100c021     	add	w1, w1, #48
  200198: 1a833021     	csel	w1, w1, w3, lo
  20019c: 3900cfe1     	strb	w1, [sp, #51]
  2001a0: b4000c42     	cbz	x2, 0x200328 <puthex+0x268>
  2001a4: 12000c41     	and	w1, w2, #0xf
  2001a8: d358fc02     	lsr	x2, x0, #24
  2001ac: 7100283f     	cmp	w1, #10
  2001b0: 11015c23     	add	w3, w1, #87
  2001b4: 1100c021     	add	w1, w1, #48
  2001b8: 1a833021     	csel	w1, w1, w3, lo
  2001bc: 3900cbe1     	strb	w1, [sp, #50]
  2001c0: b4000b82     	cbz	x2, 0x200330 <puthex+0x270>
  2001c4: 12000c41     	and	w1, w2, #0xf
  2001c8: d35cfc02     	lsr	x2, x0, #28
  2001cc: 7100283f     	cmp	w1, #10
  2001d0: 11015c23     	add	w3, w1, #87
  2001d4: 1100c021     	add	w1, w1, #48
  2001d8: 1a833021     	csel	w1, w1, w3, lo
  2001dc: 3900c7e1     	strb	w1, [sp, #49]
  2001e0: b4000ac2     	cbz	x2, 0x200338 <puthex+0x278>
  2001e4: 12000c41     	and	w1, w2, #0xf
  2001e8: d360fc02     	lsr	x2, x0, #32
  2001ec: 7100283f     	cmp	w1, #10
  2001f0: 11015c23     	add	w3, w1, #87
  2001f4: 1100c021     	add	w1, w1, #48
  2001f8: 1a833021     	csel	w1, w1, w3, lo
  2001fc: 3900c3e1     	strb	w1, [sp, #48]
  200200: b4000842     	cbz	x2, 0x200308 <puthex+0x248>
  200204: 12000c41     	and	w1, w2, #0xf
  200208: d364fc02     	lsr	x2, x0, #36
  20020c: 7100283f     	cmp	w1, #10
  200210: 11015c23     	add	w3, w1, #87
  200214: 1100c021     	add	w1, w1, #48
  200218: 1a833021     	csel	w1, w1, w3, lo
  20021c: 3900bfe1     	strb	w1, [sp, #47]
  200220: b4000902     	cbz	x2, 0x200340 <puthex+0x280>
  200224: 12000c41     	and	w1, w2, #0xf
  200228: d368fc02     	lsr	x2, x0, #40
  20022c: 7100283f     	cmp	w1, #10
  200230: 11015c23     	add	w3, w1, #87
  200234: 1100c021     	add	w1, w1, #48
  200238: 1a833021     	csel	w1, w1, w3, lo
  20023c: 3900bbe1     	strb	w1, [sp, #46]
  200240: b4000842     	cbz	x2, 0x200348 <puthex+0x288>
  200244: 12000c41     	and	w1, w2, #0xf
  200248: d36cfc02     	lsr	x2, x0, #44
  20024c: 7100283f     	cmp	w1, #10
  200250: 11015c23     	add	w3, w1, #87
  200254: 1100c021     	add	w1, w1, #48
  200258: 1a833021     	csel	w1, w1, w3, lo
  20025c: 3900b7e1     	strb	w1, [sp, #45]
  200260: b4000782     	cbz	x2, 0x200350 <puthex+0x290>
  200264: 12000c41     	and	w1, w2, #0xf
  200268: d370fc02     	lsr	x2, x0, #48
  20026c: 7100283f     	cmp	w1, #10
  200270: 11015c23     	add	w3, w1, #87
  200274: 1100c021     	add	w1, w1, #48
  200278: 1a833021     	csel	w1, w1, w3, lo
  20027c: 3900b3e1     	strb	w1, [sp, #44]
  200280: b40006c2     	cbz	x2, 0x200358 <puthex+0x298>
  200284: 12000c41     	and	w1, w2, #0xf
  200288: d374fc02     	lsr	x2, x0, #52
  20028c: 7100283f     	cmp	w1, #10
  200290: 11015c23     	add	w3, w1, #87
  200294: 1100c021     	add	w1, w1, #48
  200298: 1a833021     	csel	w1, w1, w3, lo
  20029c: 3900afe1     	strb	w1, [sp, #43]
  2002a0: b4000602     	cbz	x2, 0x200360 <puthex+0x2a0>
  2002a4: 12000c41     	and	w1, w2, #0xf
  2002a8: d378fc02     	lsr	x2, x0, #56
  2002ac: 7100283f     	cmp	w1, #10
  2002b0: 11015c23     	add	w3, w1, #87
  2002b4: 1100c021     	add	w1, w1, #48
  2002b8: 1a833021     	csel	w1, w1, w3, lo
  2002bc: 3900abe1     	strb	w1, [sp, #42]
  2002c0: b4000542     	cbz	x2, 0x200368 <puthex+0x2a8>
  2002c4: 12000c41     	and	w1, w2, #0xf
  2002c8: d37cfc00     	lsr	x0, x0, #60
  2002cc: 7100283f     	cmp	w1, #10
  2002d0: 11015c22     	add	w2, w1, #87
  2002d4: 1100c021     	add	w1, w1, #48
  2002d8: 1a823021     	csel	w1, w1, w2, lo
  2002dc: 3900a7e1     	strb	w1, [sp, #41]
  2002e0: b4000480     	cbz	x0, 0x200370 <puthex+0x2b0>
  2002e4: 7100241f     	cmp	w0, #9
  2002e8: 1100c001     	add	w1, w0, #48
  2002ec: 11015c00     	add	w0, w0, #87
  2002f0: d2800013     	mov	x19, #0
  2002f4: 1a818000     	csel	w0, w0, w1, hi
  2002f8: 3900a3e0     	strb	w0, [sp, #40]
  2002fc: 17ffff79     	b	0x2000e0 <puthex+0x20>
  200300: d28001f3     	mov	x19, #15
  200304: 17ffff77     	b	0x2000e0 <puthex+0x20>
  200308: d2800113     	mov	x19, #8
  20030c: 17ffff75     	b	0x2000e0 <puthex+0x20>
  200310: d28001d3     	mov	x19, #14
  200314: 17ffff73     	b	0x2000e0 <puthex+0x20>
  200318: d28001b3     	mov	x19, #13
  20031c: 17ffff71     	b	0x2000e0 <puthex+0x20>
  200320: d2800193     	mov	x19, #12
  200324: 17ffff6f     	b	0x2000e0 <puthex+0x20>
  200328: d2800173     	mov	x19, #11
  20032c: 17ffff6d     	b	0x2000e0 <puthex+0x20>
  200330: d2800153     	mov	x19, #10
  200334: 17ffff6b     	b	0x2000e0 <puthex+0x20>
  200338: d2800133     	mov	x19, #9
  20033c: 17ffff69     	b	0x2000e0 <puthex+0x20>
  200340: d28000f3     	mov	x19, #7
  200344: 17ffff67     	b	0x2000e0 <puthex+0x20>
  200348: d28000d3     	mov	x19, #6
  20034c: 17ffff65     	b	0x2000e0 <puthex+0x20>
  200350: d28000b3     	mov	x19, #5
  200354: 17ffff63     	b	0x2000e0 <puthex+0x20>
  200358: d2800093     	mov	x19, #4
  20035c: 17ffff61     	b	0x2000e0 <puthex+0x20>
  200360: d2800073     	mov	x19, #3
  200364: 17ffff5f     	b	0x2000e0 <puthex+0x20>
  200368: d2800053     	mov	x19, #2
  20036c: 17ffff5d     	b	0x2000e0 <puthex+0x20>
  200370: d2800033     	mov	x19, #1
  200374: 17ffff5b     	b	0x2000e0 <puthex+0x20>
  200378: d503201f     	nop
  20037c: d503201f     	nop

0000000000200380 <putdec>:
  200380: a9bd7bfd     	stp	x29, x30, [sp, #-48]!
  200384: 910003fd     	mov	x29, sp
  200388: 3900b3ff     	strb	wzr, [sp, #44]
  20038c: b5000120     	cbnz	x0, 0x2003b0 <putdec+0x30>
  200390: 910063e6     	add	x6, sp, #24
  200394: d2800263     	mov	x3, #19
  200398: 52800600     	mov	w0, #48
  20039c: 3900afe0     	strb	w0, [sp, #43]
  2003a0: 8b0300c0     	add	x0, x6, x3
  2003a4: 94000833     	bl	0x202470 <microkit_dbg_puts>
  2003a8: a8c37bfd     	ldp	x29, x30, [sp], #48
  2003ac: d65f03c0     	ret
  2003b0: 910063e6     	add	x6, sp, #24
  2003b4: b202e7e5     	mov	x5, #-3689348814741910324
  2003b8: aa0603e4     	mov	x4, x6
  2003bc: 52800283     	mov	w3, #20
  2003c0: f29999a5     	movk	x5, #52429
  2003c4: d503201f     	nop
  2003c8: 9bc57c02     	umulh	x2, x0, x5
  2003cc: 51000463     	sub	w3, w3, #1
  2003d0: 7100007f     	cmp	w3, #0
  2003d4: d1000484     	sub	x4, x4, #1
  2003d8: fa49c800     	ccmp	x0, #9, #0, gt
  2003dc: d343fc42     	lsr	x2, x2, #3
  2003e0: 8b020841     	add	x1, x2, x2, lsl #2
  2003e4: cb010401     	sub	x1, x0, x1, lsl #1
  2003e8: aa0203e0     	mov	x0, x2
  2003ec: 1100c021     	add	w1, w1, #48
  2003f0: 39005081     	strb	w1, [x4, #20]
  2003f4: 54fffea8     	b.hi	0x2003c8 <putdec+0x48>
  2003f8: 93407c63     	sxtw	x3, w3
  2003fc: 8b0300c0     	add	x0, x6, x3
  200400: 9400081c     	bl	0x202470 <microkit_dbg_puts>
  200404: a8c37bfd     	ldp	x29, x30, [sp], #48
  200408: d65f03c0     	ret
  20040c: d503201f     	nop

0000000000200410 <memcmp_custom>:
  200410: 7100005f     	cmp	w2, #0
  200414: 540001ad     	b.le	0x200448 <memcmp_custom+0x38>
  200418: 93407c45     	sxtw	x5, w2
  20041c: d2800002     	mov	x2, #0
  200420: 14000003     	b	0x20042c <memcmp_custom+0x1c>
  200424: eb0200bf     	cmp	x5, x2
  200428: 54000100     	b.eq	0x200448 <memcmp_custom+0x38>
  20042c: 38626803     	ldrb	w3, [x0, x2]
  200430: 38626824     	ldrb	w4, [x1, x2]
  200434: 91000442     	add	x2, x2, #1
  200438: 6b04007f     	cmp	w3, w4
  20043c: 54ffff40     	b.eq	0x200424 <memcmp_custom+0x14>
  200440: 4b040060     	sub	w0, w3, w4
  200444: d65f03c0     	ret
  200448: 52800000     	mov	w0, #0
  20044c: d65f03c0     	ret

0000000000200450 <get_elf_type>:
  200450: 92403c00     	and	x0, x0, #0xffff
  200454: 7100101f     	cmp	w0, #4
  200458: 540000a8     	b.hi	0x20046c <get_elf_type+0x1c>
  20045c: d0000001     	adrp	x1, 0x202000 <get_elf_type+0x14>
  200460: 911f2021     	add	x1, x1, #1992
  200464: f8607820     	ldr	x0, [x1, x0, lsl #3]
  200468: d65f03c0     	ret
  20046c: d0000000     	adrp	x0, 0x202000 <get_elf_type+0x24>
  200470: 91222000     	add	x0, x0, #2184
  200474: d65f03c0     	ret
  200478: d503201f     	nop
  20047c: d503201f     	nop

0000000000200480 <get_elf_data_encoding>:
  200480: 12001c00     	and	w0, w0, #0xff
  200484: 7100041f     	cmp	w0, #1
  200488: 54000100     	b.eq	0x2004a8 <get_elf_data_encoding+0x28>
  20048c: 7100081f     	cmp	w0, #2
  200490: d0000001     	adrp	x1, 0x202000 <get_elf_data_encoding+0x18>
  200494: 9122c021     	add	x1, x1, #2224
  200498: d0000000     	adrp	x0, 0x202000 <get_elf_data_encoding+0x20>
  20049c: 91228000     	add	x0, x0, #2208
  2004a0: 9a810000     	csel	x0, x0, x1, eq
  2004a4: d65f03c0     	ret
  2004a8: d0000000     	adrp	x0, 0x202000 <get_elf_data_encoding+0x30>
  2004ac: 91224000     	add	x0, x0, #2192
  2004b0: d65f03c0     	ret
  2004b4: d503201f     	nop
  2004b8: d503201f     	nop
  2004bc: d503201f     	nop

00000000002004c0 <get_elf_osabi>:
  2004c0: 12001c00     	and	w0, w0, #0xff
  2004c4: d0000001     	adrp	x1, 0x202000 <get_elf_osabi+0xc>
  2004c8: 9122e021     	add	x1, x1, #2232
  2004cc: 71000c1f     	cmp	w0, #3
  2004d0: d0000000     	adrp	x0, 0x202000 <get_elf_osabi+0x18>
  2004d4: 9122c000     	add	x0, x0, #2224
  2004d8: 9a811000     	csel	x0, x0, x1, ne
  2004dc: d65f03c0     	ret

00000000002004e0 <get_elf_version>:
  2004e0: 7100041f     	cmp	w0, #1
  2004e4: d0000001     	adrp	x1, 0x202000 <get_elf_version+0xc>
  2004e8: 91232021     	add	x1, x1, #2248
  2004ec: d0000000     	adrp	x0, 0x202000 <get_elf_version+0x14>
  2004f0: 9122c000     	add	x0, x0, #2224
  2004f4: 9a811000     	csel	x0, x0, x1, ne
  2004f8: d65f03c0     	ret
  2004fc: d503201f     	nop

0000000000200500 <print_elf>:
  200500: a9ba7bfd     	stp	x29, x30, [sp, #-96]!
  200504: 910003fd     	mov	x29, sp
  200508: a90153f3     	stp	x19, x20, [sp, #16]
  20050c: cb000034     	sub	x20, x1, x0
  200510: f1010e9f     	cmp	x20, #67
  200514: 5400358d     	b.le	0x200bc4 <print_elf+0x6c4>
  200518: aa0003f3     	mov	x19, x0
  20051c: 39400000     	ldrb	w0, [x0]
  200520: 7101fc1f     	cmp	w0, #127
  200524: 540035a1     	b.ne	0x200bd8 <print_elf+0x6d8>
  200528: 39400660     	ldrb	w0, [x19, #1]
  20052c: 7101141f     	cmp	w0, #69
  200530: 54003541     	b.ne	0x200bd8 <print_elf+0x6d8>
  200534: 39400a60     	ldrb	w0, [x19, #2]
  200538: 7101301f     	cmp	w0, #76
  20053c: 540034e1     	b.ne	0x200bd8 <print_elf+0x6d8>
  200540: 39400e60     	ldrb	w0, [x19, #3]
  200544: 7101181f     	cmp	w0, #70
  200548: 54003481     	b.ne	0x200bd8 <print_elf+0x6d8>
  20054c: 39401260     	ldrb	w0, [x19, #4]
  200550: 7100041f     	cmp	w0, #1
  200554: 540034c0     	b.eq	0x200bec <print_elf+0x6ec>
  200558: 7100081f     	cmp	w0, #2
  20055c: 540032a1     	b.ne	0x200bb0 <print_elf+0x6b0>
  200560: d0000000     	adrp	x0, 0x202000 <print_elf+0x68>
  200564: 91302000     	add	x0, x0, #3080
  200568: a9025bf5     	stp	x21, x22, [sp, #32]
  20056c: a90363f7     	stp	x23, x24, [sp, #48]
  200570: aa0103f7     	mov	x23, x1
  200574: 940007bf     	bl	0x202470 <microkit_dbg_puts>
  200578: d0000000     	adrp	x0, 0x202000 <print_elf+0x80>
  20057c: 9130c000     	add	x0, x0, #3120
  200580: 940007bc     	bl	0x202470 <microkit_dbg_puts>
  200584: 390163ff     	strb	wzr, [sp, #88]
  200588: 12000e60     	and	w0, w19, #0xf
  20058c: 7100281f     	cmp	w0, #10
  200590: 11015c01     	add	w1, w0, #87
  200594: 1100c000     	add	w0, w0, #48
  200598: 1a813000     	csel	w0, w0, w1, lo
  20059c: 39015fe0     	strb	w0, [sp, #87]
  2005a0: d344fe60     	lsr	x0, x19, #4
  2005a4: b400ae20     	cbz	x0, 0x201b68 <print_elf+0x1668>
  2005a8: 12000c00     	and	w0, w0, #0xf
  2005ac: d348fe61     	lsr	x1, x19, #8
  2005b0: 7100281f     	cmp	w0, #10
  2005b4: 11015c02     	add	w2, w0, #87
  2005b8: 1100c000     	add	w0, w0, #48
  2005bc: 1a823000     	csel	w0, w0, w2, lo
  2005c0: 39015be0     	strb	w0, [sp, #86]
  2005c4: b400ad61     	cbz	x1, 0x201b70 <print_elf+0x1670>
  2005c8: 12000c20     	and	w0, w1, #0xf
  2005cc: d34cfe61     	lsr	x1, x19, #12
  2005d0: 7100281f     	cmp	w0, #10
  2005d4: 11015c02     	add	w2, w0, #87
  2005d8: 1100c000     	add	w0, w0, #48
  2005dc: 1a823000     	csel	w0, w0, w2, lo
  2005e0: 390157e0     	strb	w0, [sp, #85]
  2005e4: b4004f41     	cbz	x1, 0x200fcc <print_elf+0xacc>
  2005e8: 12000c20     	and	w0, w1, #0xf
  2005ec: d350fe61     	lsr	x1, x19, #16
  2005f0: 7100281f     	cmp	w0, #10
  2005f4: 11015c02     	add	w2, w0, #87
  2005f8: 1100c000     	add	w0, w0, #48
  2005fc: 1a823000     	csel	w0, w0, w2, lo
  200600: 390153e0     	strb	w0, [sp, #84]
  200604: b400aba1     	cbz	x1, 0x201b78 <print_elf+0x1678>
  200608: 12000c20     	and	w0, w1, #0xf
  20060c: d354fe61     	lsr	x1, x19, #20
  200610: 7100281f     	cmp	w0, #10
  200614: 11015c02     	add	w2, w0, #87
  200618: 1100c000     	add	w0, w0, #48
  20061c: 1a823000     	csel	w0, w0, w2, lo
  200620: 39014fe0     	strb	w0, [sp, #83]
  200624: b400aae1     	cbz	x1, 0x201b80 <print_elf+0x1680>
  200628: 12000c20     	and	w0, w1, #0xf
  20062c: d358fe61     	lsr	x1, x19, #24
  200630: 7100281f     	cmp	w0, #10
  200634: 11015c02     	add	w2, w0, #87
  200638: 1100c000     	add	w0, w0, #48
  20063c: 1a823000     	csel	w0, w0, w2, lo
  200640: 39014be0     	strb	w0, [sp, #82]
  200644: b400aa21     	cbz	x1, 0x201b88 <print_elf+0x1688>
  200648: 12000c20     	and	w0, w1, #0xf
  20064c: d35cfe61     	lsr	x1, x19, #28
  200650: 7100281f     	cmp	w0, #10
  200654: 11015c02     	add	w2, w0, #87
  200658: 1100c000     	add	w0, w0, #48
  20065c: 1a823000     	csel	w0, w0, w2, lo
  200660: 390147e0     	strb	w0, [sp, #81]
  200664: b400a961     	cbz	x1, 0x201b90 <print_elf+0x1690>
  200668: 12000c20     	and	w0, w1, #0xf
  20066c: d360fe61     	lsr	x1, x19, #32
  200670: 7100281f     	cmp	w0, #10
  200674: 11015c02     	add	w2, w0, #87
  200678: 1100c000     	add	w0, w0, #48
  20067c: 1a823000     	csel	w0, w0, w2, lo
  200680: 390143e0     	strb	w0, [sp, #80]
  200684: b400a901     	cbz	x1, 0x201ba4 <print_elf+0x16a4>
  200688: 12000c20     	and	w0, w1, #0xf
  20068c: d364fe61     	lsr	x1, x19, #36
  200690: 7100281f     	cmp	w0, #10
  200694: 11015c02     	add	w2, w0, #87
  200698: 1100c000     	add	w0, w0, #48
  20069c: 1a823000     	csel	w0, w0, w2, lo
  2006a0: 39013fe0     	strb	w0, [sp, #79]
  2006a4: b400a901     	cbz	x1, 0x201bc4 <print_elf+0x16c4>
  2006a8: 12000c20     	and	w0, w1, #0xf
  2006ac: d368fe61     	lsr	x1, x19, #40
  2006b0: 7100281f     	cmp	w0, #10
  2006b4: 11015c02     	add	w2, w0, #87
  2006b8: 1100c000     	add	w0, w0, #48
  2006bc: 1a823000     	csel	w0, w0, w2, lo
  2006c0: 39013be0     	strb	w0, [sp, #78]
  2006c4: b400a841     	cbz	x1, 0x201bcc <print_elf+0x16cc>
  2006c8: 12000c20     	and	w0, w1, #0xf
  2006cc: d36cfe61     	lsr	x1, x19, #44
  2006d0: 7100281f     	cmp	w0, #10
  2006d4: 11015c02     	add	w2, w0, #87
  2006d8: 1100c000     	add	w0, w0, #48
  2006dc: 1a823000     	csel	w0, w0, w2, lo
  2006e0: 390137e0     	strb	w0, [sp, #77]
  2006e4: b400a841     	cbz	x1, 0x201bec <print_elf+0x16ec>
  2006e8: 12000c20     	and	w0, w1, #0xf
  2006ec: d370fe61     	lsr	x1, x19, #48
  2006f0: 7100281f     	cmp	w0, #10
  2006f4: 11015c02     	add	w2, w0, #87
  2006f8: 1100c000     	add	w0, w0, #48
  2006fc: 1a823000     	csel	w0, w0, w2, lo
  200700: 390133e0     	strb	w0, [sp, #76]
  200704: b400a781     	cbz	x1, 0x201bf4 <print_elf+0x16f4>
  200708: 12000c20     	and	w0, w1, #0xf
  20070c: d374fe61     	lsr	x1, x19, #52
  200710: 7100281f     	cmp	w0, #10
  200714: 11015c02     	add	w2, w0, #87
  200718: 1100c000     	add	w0, w0, #48
  20071c: 1a823000     	csel	w0, w0, w2, lo
  200720: 39012fe0     	strb	w0, [sp, #75]
  200724: b400a781     	cbz	x1, 0x201c14 <print_elf+0x1714>
  200728: 12000c20     	and	w0, w1, #0xf
  20072c: d378fe61     	lsr	x1, x19, #56
  200730: 7100281f     	cmp	w0, #10
  200734: 11015c02     	add	w2, w0, #87
  200738: 1100c000     	add	w0, w0, #48
  20073c: 1a823000     	csel	w0, w0, w2, lo
  200740: 39012be0     	strb	w0, [sp, #74]
  200744: b4004481     	cbz	x1, 0x200fd4 <print_elf+0xad4>
  200748: 12000c20     	and	w0, w1, #0xf
  20074c: d37cfe61     	lsr	x1, x19, #60
  200750: 7100281f     	cmp	w0, #10
  200754: 11015c02     	add	w2, w0, #87
  200758: 1100c000     	add	w0, w0, #48
  20075c: 1a823000     	csel	w0, w0, w2, lo
  200760: 390127e0     	strb	w0, [sp, #73]
  200764: b400a721     	cbz	x1, 0x201c48 <print_elf+0x1748>
  200768: 7100243f     	cmp	w1, #9
  20076c: 1100c022     	add	w2, w1, #48
  200770: 11015c20     	add	w0, w1, #87
  200774: 52800018     	mov	w24, #0
  200778: 1a828000     	csel	w0, w0, w2, hi
  20077c: 390123e0     	strb	w0, [sp, #72]
  200780: d0000016     	adrp	x22, 0x202000 <print_elf+0x288>
  200784: 912202d6     	add	x22, x22, #2176
  200788: aa1603e0     	mov	x0, x22
  20078c: 94000739     	bl	0x202470 <microkit_dbg_puts>
  200790: 910123f5     	add	x21, sp, #72
  200794: 93407f00     	sxtw	x0, w24
  200798: 8b0002a0     	add	x0, x21, x0
  20079c: 94000735     	bl	0x202470 <microkit_dbg_puts>
  2007a0: 52800140     	mov	w0, #10
  2007a4: 94000727     	bl	0x202440 <microkit_dbg_putc>
  2007a8: d0000000     	adrp	x0, 0x202000 <print_elf+0x2b0>
  2007ac: 91316000     	add	x0, x0, #3160
  2007b0: 94000730     	bl	0x202470 <microkit_dbg_puts>
  2007b4: 390163ff     	strb	wzr, [sp, #88]
  2007b8: b5004397     	cbnz	x23, 0x201028 <print_elf+0xb28>
  2007bc: 52800600     	mov	w0, #48
  2007c0: d28001f7     	mov	x23, #15
  2007c4: 39015fe0     	strb	w0, [sp, #87]
  2007c8: aa1603e0     	mov	x0, x22
  2007cc: 94000729     	bl	0x202470 <microkit_dbg_puts>
  2007d0: 8b1702a0     	add	x0, x21, x23
  2007d4: 94000727     	bl	0x202470 <microkit_dbg_puts>
  2007d8: 52800140     	mov	w0, #10
  2007dc: 94000719     	bl	0x202440 <microkit_dbg_putc>
  2007e0: d0000000     	adrp	x0, 0x202000 <print_elf+0x2e8>
  2007e4: 91320000     	add	x0, x0, #3200
  2007e8: 94000722     	bl	0x202470 <microkit_dbg_puts>
  2007ec: 390173ff     	strb	wzr, [sp, #92]
  2007f0: b202e7e5     	mov	x5, #-3689348814741910324
  2007f4: aa1403e1     	mov	x1, x20
  2007f8: aa1503e4     	mov	x4, x21
  2007fc: 52800280     	mov	w0, #20
  200800: f29999a5     	movk	x5, #52429
  200804: 9bc57c23     	umulh	x3, x1, x5
  200808: 51000400     	sub	w0, w0, #1
  20080c: 7100001f     	cmp	w0, #0
  200810: d1000484     	sub	x4, x4, #1
  200814: fa49c820     	ccmp	x1, #9, #0, gt
  200818: d343fc63     	lsr	x3, x3, #3
  20081c: 8b030862     	add	x2, x3, x3, lsl #2
  200820: cb020422     	sub	x2, x1, x2, lsl #1
  200824: aa0303e1     	mov	x1, x3
  200828: 1100c042     	add	w2, w2, #48
  20082c: 39005082     	strb	w2, [x4, #20]
  200830: 54fffea8     	b.hi	0x200804 <print_elf+0x304>
  200834: 8b20c2a0     	add	x0, x21, w0, sxtw
  200838: d0000014     	adrp	x20, 0x202000 <print_elf+0x340>
  20083c: 912cc294     	add	x20, x20, #2864
  200840: 9400070c     	bl	0x202470 <microkit_dbg_puts>
  200844: aa1403e0     	mov	x0, x20
  200848: 9400070a     	bl	0x202470 <microkit_dbg_puts>
  20084c: d0000000     	adrp	x0, 0x202000 <print_elf+0x354>
  200850: 9132a000     	add	x0, x0, #3240
  200854: 94000707     	bl	0x202470 <microkit_dbg_puts>
  200858: d0000000     	adrp	x0, 0x202000 <print_elf+0x360>
  20085c: 91262000     	add	x0, x0, #2440
  200860: 94000704     	bl	0x202470 <microkit_dbg_puts>
  200864: 39401660     	ldrb	w0, [x19, #5]
  200868: 7100041f     	cmp	w0, #1
  20086c: 54004e60     	b.eq	0x201238 <print_elf+0xd38>
  200870: 7100081f     	cmp	w0, #2
  200874: d0000001     	adrp	x1, 0x202000 <print_elf+0x37c>
  200878: 9122c021     	add	x1, x1, #2224
  20087c: d0000000     	adrp	x0, 0x202000 <print_elf+0x384>
  200880: 91228000     	add	x0, x0, #2208
  200884: 9a810000     	csel	x0, x0, x1, eq
  200888: 940006fa     	bl	0x202470 <microkit_dbg_puts>
  20088c: 52800140     	mov	w0, #10
  200890: 940006ec     	bl	0x202440 <microkit_dbg_putc>
  200894: d0000000     	adrp	x0, 0x202000 <print_elf+0x39c>
  200898: 9126c000     	add	x0, x0, #2480
  20089c: 940006f5     	bl	0x202470 <microkit_dbg_puts>
  2008a0: 390173ff     	strb	wzr, [sp, #92]
  2008a4: 39401a62     	ldrb	w2, [x19, #6]
  2008a8: b50039a2     	cbnz	x2, 0x200fdc <print_elf+0xadc>
  2008ac: 52800601     	mov	w1, #48
  2008b0: d2800260     	mov	x0, #19
  2008b4: 39016fe1     	strb	w1, [sp, #91]
  2008b8: 8b0002a0     	add	x0, x21, x0
  2008bc: 940006ed     	bl	0x202470 <microkit_dbg_puts>
  2008c0: 52800140     	mov	w0, #10
  2008c4: 940006df     	bl	0x202440 <microkit_dbg_putc>
  2008c8: d0000000     	adrp	x0, 0x202000 <print_elf+0x3d0>
  2008cc: 91276000     	add	x0, x0, #2520
  2008d0: 940006e8     	bl	0x202470 <microkit_dbg_puts>
  2008d4: 39401e60     	ldrb	w0, [x19, #7]
  2008d8: d0000001     	adrp	x1, 0x202000 <print_elf+0x3e0>
  2008dc: 9122e021     	add	x1, x1, #2232
  2008e0: 71000c1f     	cmp	w0, #3
  2008e4: d0000000     	adrp	x0, 0x202000 <print_elf+0x3ec>
  2008e8: 9122c000     	add	x0, x0, #2224
  2008ec: 9a811000     	csel	x0, x0, x1, ne
  2008f0: 940006e0     	bl	0x202470 <microkit_dbg_puts>
  2008f4: 52800140     	mov	w0, #10
  2008f8: 940006d2     	bl	0x202440 <microkit_dbg_putc>
  2008fc: 39401a60     	ldrb	w0, [x19, #6]
  200900: 7100041f     	cmp	w0, #1
  200904: 54003281     	b.ne	0x200f54 <print_elf+0xa54>
  200908: d0000000     	adrp	x0, 0x202000 <print_elf+0x410>
  20090c: 9128a000     	add	x0, x0, #2600
  200910: 940006d8     	bl	0x202470 <microkit_dbg_puts>
  200914: 79402260     	ldrh	w0, [x19, #16]
  200918: 7100101f     	cmp	w0, #4
  20091c: 54005928     	b.hi	0x201440 <print_elf+0xf40>
  200920: d0000001     	adrp	x1, 0x202000 <print_elf+0x428>
  200924: 911f2021     	add	x1, x1, #1992
  200928: f8607820     	ldr	x0, [x1, x0, lsl #3]
  20092c: 940006d1     	bl	0x202470 <microkit_dbg_puts>
  200930: 52800140     	mov	w0, #10
  200934: 940006c3     	bl	0x202440 <microkit_dbg_putc>
  200938: d0000000     	adrp	x0, 0x202000 <print_elf+0x440>
  20093c: 91294000     	add	x0, x0, #2640
  200940: 940006cc     	bl	0x202470 <microkit_dbg_puts>
  200944: 390163ff     	strb	wzr, [sp, #88]
  200948: f9400e60     	ldr	x0, [x19, #24]
  20094c: b50047c0     	cbnz	x0, 0x201244 <print_elf+0xd44>
  200950: 52800600     	mov	w0, #48
  200954: d28001f7     	mov	x23, #15
  200958: 39015fe0     	strb	w0, [sp, #87]
  20095c: aa1603e0     	mov	x0, x22
  200960: 940006c4     	bl	0x202470 <microkit_dbg_puts>
  200964: 8b1702a0     	add	x0, x21, x23
  200968: 940006c2     	bl	0x202470 <microkit_dbg_puts>
  20096c: 52800140     	mov	w0, #10
  200970: 940006b4     	bl	0x202440 <microkit_dbg_putc>
  200974: d0000000     	adrp	x0, 0x202000 <print_elf+0x47c>
  200978: 9129e000     	add	x0, x0, #2680
  20097c: 940006bd     	bl	0x202470 <microkit_dbg_puts>
  200980: 390173ff     	strb	wzr, [sp, #92]
  200984: f9401262     	ldr	x2, [x19, #32]
  200988: b5006c02     	cbnz	x2, 0x201708 <print_elf+0x1208>
  20098c: 52800601     	mov	w1, #48
  200990: d2800260     	mov	x0, #19
  200994: 39016fe1     	strb	w1, [sp, #91]
  200998: 8b0002a0     	add	x0, x21, x0
  20099c: d0000017     	adrp	x23, 0x202000 <print_elf+0x4a4>
  2009a0: 912a82f7     	add	x23, x23, #2720
  2009a4: 940006b3     	bl	0x202470 <microkit_dbg_puts>
  2009a8: aa1703e0     	mov	x0, x23
  2009ac: 940006b1     	bl	0x202470 <microkit_dbg_puts>
  2009b0: d0000000     	adrp	x0, 0x202000 <print_elf+0x4b8>
  2009b4: 912ae000     	add	x0, x0, #2744
  2009b8: 940006ae     	bl	0x202470 <microkit_dbg_puts>
  2009bc: 390173ff     	strb	wzr, [sp, #92]
  2009c0: f9401662     	ldr	x2, [x19, #40]
  2009c4: b50067e2     	cbnz	x2, 0x2016c0 <print_elf+0x11c0>
  2009c8: 52800601     	mov	w1, #48
  2009cc: d2800260     	mov	x0, #19
  2009d0: 39016fe1     	strb	w1, [sp, #91]
  2009d4: 8b0002a0     	add	x0, x21, x0
  2009d8: 940006a6     	bl	0x202470 <microkit_dbg_puts>
  2009dc: aa1703e0     	mov	x0, x23
  2009e0: 940006a4     	bl	0x202470 <microkit_dbg_puts>
  2009e4: d0000000     	adrp	x0, 0x202000 <print_elf+0x4ec>
  2009e8: 912b8000     	add	x0, x0, #2784
  2009ec: 940006a1     	bl	0x202470 <microkit_dbg_puts>
  2009f0: 390163ff     	strb	wzr, [sp, #88]
  2009f4: b9403260     	ldr	w0, [x19, #48]
  2009f8: 2a0003e1     	mov	w1, w0
  2009fc: 35005de0     	cbnz	w0, 0x2015b8 <print_elf+0x10b8>
  200a00: 52800600     	mov	w0, #48
  200a04: d28001f7     	mov	x23, #15
  200a08: 39015fe0     	strb	w0, [sp, #87]
  200a0c: aa1603e0     	mov	x0, x22
  200a10: 94000698     	bl	0x202470 <microkit_dbg_puts>
  200a14: 8b1702a0     	add	x0, x21, x23
  200a18: 94000696     	bl	0x202470 <microkit_dbg_puts>
  200a1c: 52800140     	mov	w0, #10
  200a20: 94000688     	bl	0x202440 <microkit_dbg_putc>
  200a24: d0000000     	adrp	x0, 0x202000 <print_elf+0x52c>
  200a28: 912c2000     	add	x0, x0, #2824
  200a2c: 94000691     	bl	0x202470 <microkit_dbg_puts>
  200a30: 390173ff     	strb	wzr, [sp, #92]
  200a34: 79406a62     	ldrh	w2, [x19, #52]
  200a38: b50059c2     	cbnz	x2, 0x201570 <print_elf+0x1070>
  200a3c: 52800601     	mov	w1, #48
  200a40: d2800260     	mov	x0, #19
  200a44: 39016fe1     	strb	w1, [sp, #91]
  200a48: 8b0002a0     	add	x0, x21, x0
  200a4c: 94000689     	bl	0x202470 <microkit_dbg_puts>
  200a50: aa1403e0     	mov	x0, x20
  200a54: 94000687     	bl	0x202470 <microkit_dbg_puts>
  200a58: d0000000     	adrp	x0, 0x202000 <print_elf+0x560>
  200a5c: 912d0000     	add	x0, x0, #2880
  200a60: 94000684     	bl	0x202470 <microkit_dbg_puts>
  200a64: 390173ff     	strb	wzr, [sp, #92]
  200a68: 79406e62     	ldrh	w2, [x19, #54]
  200a6c: b50055e2     	cbnz	x2, 0x201528 <print_elf+0x1028>
  200a70: 52800601     	mov	w1, #48
  200a74: d2800260     	mov	x0, #19
  200a78: 39016fe1     	strb	w1, [sp, #91]
  200a7c: 8b0002a0     	add	x0, x21, x0
  200a80: 9400067c     	bl	0x202470 <microkit_dbg_puts>
  200a84: aa1403e0     	mov	x0, x20
  200a88: 9400067a     	bl	0x202470 <microkit_dbg_puts>
  200a8c: d0000000     	adrp	x0, 0x202000 <print_elf+0x594>
  200a90: 912da000     	add	x0, x0, #2920
  200a94: 94000677     	bl	0x202470 <microkit_dbg_puts>
  200a98: 390173ff     	strb	wzr, [sp, #92]
  200a9c: 79407262     	ldrh	w2, [x19, #56]
  200aa0: b5005202     	cbnz	x2, 0x2014e0 <print_elf+0xfe0>
  200aa4: 52800601     	mov	w1, #48
  200aa8: d2800260     	mov	x0, #19
  200aac: 39016fe1     	strb	w1, [sp, #91]
  200ab0: 8b0002a0     	add	x0, x21, x0
  200ab4: 9400066f     	bl	0x202470 <microkit_dbg_puts>
  200ab8: 52800140     	mov	w0, #10
  200abc: 94000661     	bl	0x202440 <microkit_dbg_putc>
  200ac0: d0000000     	adrp	x0, 0x202000 <print_elf+0x5c8>
  200ac4: 912e4000     	add	x0, x0, #2960
  200ac8: 9400066a     	bl	0x202470 <microkit_dbg_puts>
  200acc: 390173ff     	strb	wzr, [sp, #92]
  200ad0: 79407662     	ldrh	w2, [x19, #58]
  200ad4: b5004e22     	cbnz	x2, 0x201498 <print_elf+0xf98>
  200ad8: 52800601     	mov	w1, #48
  200adc: d2800260     	mov	x0, #19
  200ae0: 39016fe1     	strb	w1, [sp, #91]
  200ae4: 8b0002a0     	add	x0, x21, x0
  200ae8: 94000662     	bl	0x202470 <microkit_dbg_puts>
  200aec: aa1403e0     	mov	x0, x20
  200af0: 94000660     	bl	0x202470 <microkit_dbg_puts>
  200af4: d0000000     	adrp	x0, 0x202000 <print_elf+0x5fc>
  200af8: 912ee000     	add	x0, x0, #3000
  200afc: 9400065d     	bl	0x202470 <microkit_dbg_puts>
  200b00: 390173ff     	strb	wzr, [sp, #92]
  200b04: 79407a62     	ldrh	w2, [x19, #60]
  200b08: b5004a22     	cbnz	x2, 0x20144c <print_elf+0xf4c>
  200b0c: 52800601     	mov	w1, #48
  200b10: d2800260     	mov	x0, #19
  200b14: 39016fe1     	strb	w1, [sp, #91]
  200b18: 8b0002a0     	add	x0, x21, x0
  200b1c: 94000655     	bl	0x202470 <microkit_dbg_puts>
  200b20: 52800140     	mov	w0, #10
  200b24: 94000647     	bl	0x202440 <microkit_dbg_putc>
  200b28: d0000000     	adrp	x0, 0x202000 <print_elf+0x630>
  200b2c: 912f8000     	add	x0, x0, #3040
  200b30: 94000650     	bl	0x202470 <microkit_dbg_puts>
  200b34: 390173ff     	strb	wzr, [sp, #92]
  200b38: 79407e62     	ldrh	w2, [x19, #62]
  200b3c: b4003762     	cbz	x2, 0x201228 <print_elf+0xd28>
  200b40: b202e7e5     	mov	x5, #-3689348814741910324
  200b44: aa1503e4     	mov	x4, x21
  200b48: 52800283     	mov	w3, #20
  200b4c: f29999a5     	movk	x5, #52429
  200b50: 9bc57c41     	umulh	x1, x2, x5
  200b54: 51000463     	sub	w3, w3, #1
  200b58: 7100007f     	cmp	w3, #0
  200b5c: d1000484     	sub	x4, x4, #1
  200b60: fa49c840     	ccmp	x2, #9, #0, gt
  200b64: d343fc21     	lsr	x1, x1, #3
  200b68: 8b010820     	add	x0, x1, x1, lsl #2
  200b6c: cb000440     	sub	x0, x2, x0, lsl #1
  200b70: aa0103e2     	mov	x2, x1
  200b74: 1100c000     	add	w0, w0, #48
  200b78: 39005080     	strb	w0, [x4, #20]
  200b7c: 54fffea8     	b.hi	0x200b50 <print_elf+0x650>
  200b80: 93407c60     	sxtw	x0, w3
  200b84: 8b0002a0     	add	x0, x21, x0
  200b88: 9400063a     	bl	0x202470 <microkit_dbg_puts>
  200b8c: 52800140     	mov	w0, #10
  200b90: 9400062c     	bl	0x202440 <microkit_dbg_putc>
  200b94: a94153f3     	ldp	x19, x20, [sp, #16]
  200b98: d0000000     	adrp	x0, 0x202000 <print_elf+0x6a0>
  200b9c: 9133e000     	add	x0, x0, #3320
  200ba0: a9425bf5     	ldp	x21, x22, [sp, #32]
  200ba4: a94363f7     	ldp	x23, x24, [sp, #48]
  200ba8: a8c67bfd     	ldp	x29, x30, [sp], #96
  200bac: 14000631     	b	0x202470 <microkit_dbg_puts>
  200bb0: a94153f3     	ldp	x19, x20, [sp, #16]
  200bb4: d0000000     	adrp	x0, 0x202000 <print_elf+0x6bc>
  200bb8: 91336000     	add	x0, x0, #3288
  200bbc: a8c67bfd     	ldp	x29, x30, [sp], #96
  200bc0: 1400062c     	b	0x202470 <microkit_dbg_puts>
  200bc4: a94153f3     	ldp	x19, x20, [sp, #16]
  200bc8: d0000000     	adrp	x0, 0x202000 <print_elf+0x6d0>
  200bcc: 91234000     	add	x0, x0, #2256
  200bd0: a8c67bfd     	ldp	x29, x30, [sp], #96
  200bd4: 14000627     	b	0x202470 <microkit_dbg_puts>
  200bd8: a94153f3     	ldp	x19, x20, [sp, #16]
  200bdc: d0000000     	adrp	x0, 0x202000 <print_elf+0x6e4>
  200be0: 91242000     	add	x0, x0, #2312
  200be4: a8c67bfd     	ldp	x29, x30, [sp], #96
  200be8: 14000622     	b	0x202470 <microkit_dbg_puts>
  200bec: d0000000     	adrp	x0, 0x202000 <print_elf+0x6f4>
  200bf0: 9124c000     	add	x0, x0, #2352
  200bf4: a9025bf5     	stp	x21, x22, [sp, #32]
  200bf8: 9400061e     	bl	0x202470 <microkit_dbg_puts>
  200bfc: d0000000     	adrp	x0, 0x202000 <print_elf+0x704>
  200c00: 91256000     	add	x0, x0, #2392
  200c04: 9400061b     	bl	0x202470 <microkit_dbg_puts>
  200c08: d0000000     	adrp	x0, 0x202000 <print_elf+0x710>
  200c0c: 91262000     	add	x0, x0, #2440
  200c10: 94000618     	bl	0x202470 <microkit_dbg_puts>
  200c14: 39401660     	ldrb	w0, [x19, #5]
  200c18: 7100041f     	cmp	w0, #1
  200c1c: 540059a0     	b.eq	0x201750 <print_elf+0x1250>
  200c20: 7100081f     	cmp	w0, #2
  200c24: d0000001     	adrp	x1, 0x202000 <print_elf+0x72c>
  200c28: 9122c021     	add	x1, x1, #2224
  200c2c: d0000000     	adrp	x0, 0x202000 <print_elf+0x734>
  200c30: 91228000     	add	x0, x0, #2208
  200c34: 9a810000     	csel	x0, x0, x1, eq
  200c38: 9400060e     	bl	0x202470 <microkit_dbg_puts>
  200c3c: 52800140     	mov	w0, #10
  200c40: 94000600     	bl	0x202440 <microkit_dbg_putc>
  200c44: d0000000     	adrp	x0, 0x202000 <print_elf+0x74c>
  200c48: 9126c000     	add	x0, x0, #2480
  200c4c: 94000609     	bl	0x202470 <microkit_dbg_puts>
  200c50: 390173ff     	strb	wzr, [sp, #92]
  200c54: 39401a62     	ldrb	w2, [x19, #6]
  200c58: b50018c2     	cbnz	x2, 0x200f70 <print_elf+0xa70>
  200c5c: 910123f5     	add	x21, sp, #72
  200c60: 52800601     	mov	w1, #48
  200c64: d2800260     	mov	x0, #19
  200c68: 39016fe1     	strb	w1, [sp, #91]
  200c6c: 8b0002a0     	add	x0, x21, x0
  200c70: 94000600     	bl	0x202470 <microkit_dbg_puts>
  200c74: 52800140     	mov	w0, #10
  200c78: 940005f2     	bl	0x202440 <microkit_dbg_putc>
  200c7c: d0000000     	adrp	x0, 0x202000 <print_elf+0x784>
  200c80: 91276000     	add	x0, x0, #2520
  200c84: 940005fb     	bl	0x202470 <microkit_dbg_puts>
  200c88: 39401e61     	ldrb	w1, [x19, #7]
  200c8c: d0000000     	adrp	x0, 0x202000 <print_elf+0x794>
  200c90: 9122e000     	add	x0, x0, #2232
  200c94: 71000c3f     	cmp	w1, #3
  200c98: d0000001     	adrp	x1, 0x202000 <print_elf+0x7a0>
  200c9c: 9122c021     	add	x1, x1, #2224
  200ca0: 9a801020     	csel	x0, x1, x0, ne
  200ca4: 940005f3     	bl	0x202470 <microkit_dbg_puts>
  200ca8: 52800140     	mov	w0, #10
  200cac: 940005e5     	bl	0x202440 <microkit_dbg_putc>
  200cb0: 39401a60     	ldrb	w0, [x19, #6]
  200cb4: 7100041f     	cmp	w0, #1
  200cb8: 54001501     	b.ne	0x200f58 <print_elf+0xa58>
  200cbc: d0000000     	adrp	x0, 0x202000 <print_elf+0x7c4>
  200cc0: 9128a000     	add	x0, x0, #2600
  200cc4: a90363f7     	stp	x23, x24, [sp, #48]
  200cc8: 940005ea     	bl	0x202470 <microkit_dbg_puts>
  200ccc: 79402260     	ldrh	w0, [x19, #16]
  200cd0: 7100101f     	cmp	w0, #4
  200cd4: 54001768     	b.hi	0x200fc0 <print_elf+0xac0>
  200cd8: d0000001     	adrp	x1, 0x202000 <print_elf+0x7e0>
  200cdc: 911f2021     	add	x1, x1, #1992
  200ce0: f8607820     	ldr	x0, [x1, x0, lsl #3]
  200ce4: 940005e3     	bl	0x202470 <microkit_dbg_puts>
  200ce8: 52800140     	mov	w0, #10
  200cec: 940005d5     	bl	0x202440 <microkit_dbg_putc>
  200cf0: d0000000     	adrp	x0, 0x202000 <print_elf+0x7f8>
  200cf4: 91294000     	add	x0, x0, #2640
  200cf8: 940005de     	bl	0x202470 <microkit_dbg_puts>
  200cfc: 390163ff     	strb	wzr, [sp, #88]
  200d00: b9401e60     	ldr	w0, [x19, #28]
  200d04: 2a0003e1     	mov	w1, w0
  200d08: 35006ac0     	cbnz	w0, 0x201a60 <print_elf+0x1560>
  200d0c: 52800600     	mov	w0, #48
  200d10: d28001f4     	mov	x20, #15
  200d14: 39015fe0     	strb	w0, [sp, #87]
  200d18: d0000016     	adrp	x22, 0x202000 <print_elf+0x820>
  200d1c: 912202d6     	add	x22, x22, #2176
  200d20: aa1603e0     	mov	x0, x22
  200d24: 940005d3     	bl	0x202470 <microkit_dbg_puts>
  200d28: 8b1402a0     	add	x0, x21, x20
  200d2c: 940005d1     	bl	0x202470 <microkit_dbg_puts>
  200d30: 52800140     	mov	w0, #10
  200d34: 940005c3     	bl	0x202440 <microkit_dbg_putc>
  200d38: d0000000     	adrp	x0, 0x202000 <print_elf+0x840>
  200d3c: 9129e000     	add	x0, x0, #2680
  200d40: 940005cc     	bl	0x202470 <microkit_dbg_puts>
  200d44: 390173ff     	strb	wzr, [sp, #92]
  200d48: b9402262     	ldr	w2, [x19, #32]
  200d4c: b5006662     	cbnz	x2, 0x201a18 <print_elf+0x1518>
  200d50: 52800601     	mov	w1, #48
  200d54: d2800260     	mov	x0, #19
  200d58: 39016fe1     	strb	w1, [sp, #91]
  200d5c: 8b0002a0     	add	x0, x21, x0
  200d60: d0000017     	adrp	x23, 0x202000 <print_elf+0x868>
  200d64: 912a82f7     	add	x23, x23, #2720
  200d68: 940005c2     	bl	0x202470 <microkit_dbg_puts>
  200d6c: aa1703e0     	mov	x0, x23
  200d70: 940005c0     	bl	0x202470 <microkit_dbg_puts>
  200d74: d0000000     	adrp	x0, 0x202000 <print_elf+0x87c>
  200d78: 912ae000     	add	x0, x0, #2744
  200d7c: 940005bd     	bl	0x202470 <microkit_dbg_puts>
  200d80: 390173ff     	strb	wzr, [sp, #92]
  200d84: b9402662     	ldr	w2, [x19, #36]
  200d88: b5006242     	cbnz	x2, 0x2019d0 <print_elf+0x14d0>
  200d8c: 52800601     	mov	w1, #48
  200d90: d2800260     	mov	x0, #19
  200d94: 39016fe1     	strb	w1, [sp, #91]
  200d98: 8b0002a0     	add	x0, x21, x0
  200d9c: 940005b5     	bl	0x202470 <microkit_dbg_puts>
  200da0: aa1703e0     	mov	x0, x23
  200da4: 940005b3     	bl	0x202470 <microkit_dbg_puts>
  200da8: d0000000     	adrp	x0, 0x202000 <print_elf+0x8b0>
  200dac: 912b8000     	add	x0, x0, #2784
  200db0: 940005b0     	bl	0x202470 <microkit_dbg_puts>
  200db4: 390163ff     	strb	wzr, [sp, #88]
  200db8: b9402a60     	ldr	w0, [x19, #40]
  200dbc: 2a0003e1     	mov	w1, w0
  200dc0: 35005840     	cbnz	w0, 0x2018c8 <print_elf+0x13c8>
  200dc4: 52800600     	mov	w0, #48
  200dc8: d28001f4     	mov	x20, #15
  200dcc: 39015fe0     	strb	w0, [sp, #87]
  200dd0: aa1603e0     	mov	x0, x22
  200dd4: 940005a7     	bl	0x202470 <microkit_dbg_puts>
  200dd8: 8b1402a0     	add	x0, x21, x20
  200ddc: 940005a5     	bl	0x202470 <microkit_dbg_puts>
  200de0: 52800140     	mov	w0, #10
  200de4: 94000597     	bl	0x202440 <microkit_dbg_putc>
  200de8: d0000000     	adrp	x0, 0x202000 <print_elf+0x8f0>
  200dec: 912c2000     	add	x0, x0, #2824
  200df0: 940005a0     	bl	0x202470 <microkit_dbg_puts>
  200df4: 390173ff     	strb	wzr, [sp, #92]
  200df8: b9402e62     	ldr	w2, [x19, #44]
  200dfc: b5005422     	cbnz	x2, 0x201880 <print_elf+0x1380>
  200e00: 52800601     	mov	w1, #48
  200e04: d2800260     	mov	x0, #19
  200e08: 39016fe1     	strb	w1, [sp, #91]
  200e0c: 8b0002a0     	add	x0, x21, x0
  200e10: d0000014     	adrp	x20, 0x202000 <print_elf+0x918>
  200e14: 912cc294     	add	x20, x20, #2864
  200e18: 94000596     	bl	0x202470 <microkit_dbg_puts>
  200e1c: aa1403e0     	mov	x0, x20
  200e20: 94000594     	bl	0x202470 <microkit_dbg_puts>
  200e24: d0000000     	adrp	x0, 0x202000 <print_elf+0x92c>
  200e28: 912d0000     	add	x0, x0, #2880
  200e2c: 94000591     	bl	0x202470 <microkit_dbg_puts>
  200e30: 390173ff     	strb	wzr, [sp, #92]
  200e34: b9403262     	ldr	w2, [x19, #48]
  200e38: b5005002     	cbnz	x2, 0x201838 <print_elf+0x1338>
  200e3c: 52800601     	mov	w1, #48
  200e40: d2800260     	mov	x0, #19
  200e44: 39016fe1     	strb	w1, [sp, #91]
  200e48: 8b0002a0     	add	x0, x21, x0
  200e4c: 94000589     	bl	0x202470 <microkit_dbg_puts>
  200e50: aa1403e0     	mov	x0, x20
  200e54: 94000587     	bl	0x202470 <microkit_dbg_puts>
  200e58: d0000000     	adrp	x0, 0x202000 <print_elf+0x960>
  200e5c: 912da000     	add	x0, x0, #2920
  200e60: 94000584     	bl	0x202470 <microkit_dbg_puts>
  200e64: 390173ff     	strb	wzr, [sp, #92]
  200e68: b9403662     	ldr	w2, [x19, #52]
  200e6c: b5004c22     	cbnz	x2, 0x2017f0 <print_elf+0x12f0>
  200e70: 52800601     	mov	w1, #48
  200e74: d2800260     	mov	x0, #19
  200e78: 39016fe1     	strb	w1, [sp, #91]
  200e7c: 8b0002a0     	add	x0, x21, x0
  200e80: 9400057c     	bl	0x202470 <microkit_dbg_puts>
  200e84: 52800140     	mov	w0, #10
  200e88: 9400056e     	bl	0x202440 <microkit_dbg_putc>
  200e8c: d0000000     	adrp	x0, 0x202000 <print_elf+0x994>
  200e90: 912e4000     	add	x0, x0, #2960
  200e94: 94000577     	bl	0x202470 <microkit_dbg_puts>
  200e98: 390173ff     	strb	wzr, [sp, #92]
  200e9c: b9403a62     	ldr	w2, [x19, #56]
  200ea0: b5004842     	cbnz	x2, 0x2017a8 <print_elf+0x12a8>
  200ea4: 52800601     	mov	w1, #48
  200ea8: d2800260     	mov	x0, #19
  200eac: 39016fe1     	strb	w1, [sp, #91]
  200eb0: 8b0002a0     	add	x0, x21, x0
  200eb4: 9400056f     	bl	0x202470 <microkit_dbg_puts>
  200eb8: aa1403e0     	mov	x0, x20
  200ebc: 9400056d     	bl	0x202470 <microkit_dbg_puts>
  200ec0: d0000000     	adrp	x0, 0x202000 <print_elf+0x9c8>
  200ec4: 912ee000     	add	x0, x0, #3000
  200ec8: 9400056a     	bl	0x202470 <microkit_dbg_puts>
  200ecc: 390173ff     	strb	wzr, [sp, #92]
  200ed0: b9403e62     	ldr	w2, [x19, #60]
  200ed4: b5004442     	cbnz	x2, 0x20175c <print_elf+0x125c>
  200ed8: 52800601     	mov	w1, #48
  200edc: d2800260     	mov	x0, #19
  200ee0: 39016fe1     	strb	w1, [sp, #91]
  200ee4: 8b0002a0     	add	x0, x21, x0
  200ee8: 94000562     	bl	0x202470 <microkit_dbg_puts>
  200eec: 52800140     	mov	w0, #10
  200ef0: 94000554     	bl	0x202440 <microkit_dbg_putc>
  200ef4: d0000000     	adrp	x0, 0x202000 <print_elf+0x9fc>
  200ef8: 912f8000     	add	x0, x0, #3040
  200efc: 9400055d     	bl	0x202470 <microkit_dbg_puts>
  200f00: 390173ff     	strb	wzr, [sp, #92]
  200f04: b9404262     	ldr	w2, [x19, #64]
  200f08: b4001902     	cbz	x2, 0x201228 <print_elf+0xd28>
  200f0c: b202e7e5     	mov	x5, #-3689348814741910324
  200f10: aa1503e4     	mov	x4, x21
  200f14: 52800283     	mov	w3, #20
  200f18: f29999a5     	movk	x5, #52429
  200f1c: d503201f     	nop
  200f20: 9bc57c41     	umulh	x1, x2, x5
  200f24: 51000463     	sub	w3, w3, #1
  200f28: 7100007f     	cmp	w3, #0
  200f2c: d1000484     	sub	x4, x4, #1
  200f30: fa49c840     	ccmp	x2, #9, #0, gt
  200f34: d343fc21     	lsr	x1, x1, #3
  200f38: 8b010820     	add	x0, x1, x1, lsl #2
  200f3c: cb000440     	sub	x0, x2, x0, lsl #1
  200f40: aa0103e2     	mov	x2, x1
  200f44: 1100c000     	add	w0, w0, #48
  200f48: 39005080     	strb	w0, [x4, #20]
  200f4c: 54fffea8     	b.hi	0x200f20 <print_elf+0xa20>
  200f50: 17ffff0c     	b	0x200b80 <print_elf+0x680>
  200f54: a94363f7     	ldp	x23, x24, [sp, #48]
  200f58: d0000000     	adrp	x0, 0x202000 <print_elf+0xa60>
  200f5c: 91280000     	add	x0, x0, #2560
  200f60: a94153f3     	ldp	x19, x20, [sp, #16]
  200f64: a9425bf5     	ldp	x21, x22, [sp, #32]
  200f68: a8c67bfd     	ldp	x29, x30, [sp], #96
  200f6c: 14000541     	b	0x202470 <microkit_dbg_puts>
  200f70: 910123f5     	add	x21, sp, #72
  200f74: b202e7e5     	mov	x5, #-3689348814741910324
  200f78: aa1503e4     	mov	x4, x21
  200f7c: 52800283     	mov	w3, #20
  200f80: f29999a5     	movk	x5, #52429
  200f84: d503201f     	nop
  200f88: 9bc57c41     	umulh	x1, x2, x5
  200f8c: 51000463     	sub	w3, w3, #1
  200f90: 7100007f     	cmp	w3, #0
  200f94: d1000484     	sub	x4, x4, #1
  200f98: fa49c840     	ccmp	x2, #9, #0, gt
  200f9c: d343fc21     	lsr	x1, x1, #3
  200fa0: 8b010820     	add	x0, x1, x1, lsl #2
  200fa4: cb000440     	sub	x0, x2, x0, lsl #1
  200fa8: aa0103e2     	mov	x2, x1
  200fac: 1100c000     	add	w0, w0, #48
  200fb0: 39005080     	strb	w0, [x4, #20]
  200fb4: 54fffea8     	b.hi	0x200f88 <print_elf+0xa88>
  200fb8: 93407c60     	sxtw	x0, w3
  200fbc: 17ffff2c     	b	0x200c6c <print_elf+0x76c>
  200fc0: d0000000     	adrp	x0, 0x202000 <print_elf+0xac8>
  200fc4: 91222000     	add	x0, x0, #2184
  200fc8: 17ffff47     	b	0x200ce4 <print_elf+0x7e4>
  200fcc: 528001b8     	mov	w24, #13
  200fd0: 17fffdec     	b	0x200780 <print_elf+0x280>
  200fd4: 52800058     	mov	w24, #2
  200fd8: 17fffdea     	b	0x200780 <print_elf+0x280>
  200fdc: b202e7e5     	mov	x5, #-3689348814741910324
  200fe0: aa1503e4     	mov	x4, x21
  200fe4: 52800283     	mov	w3, #20
  200fe8: f29999a5     	movk	x5, #52429
  200fec: d503201f     	nop
  200ff0: 9bc57c41     	umulh	x1, x2, x5
  200ff4: 51000463     	sub	w3, w3, #1
  200ff8: 7100007f     	cmp	w3, #0
  200ffc: d1000484     	sub	x4, x4, #1
  201000: fa49c840     	ccmp	x2, #9, #0, gt
  201004: d343fc21     	lsr	x1, x1, #3
  201008: 8b010820     	add	x0, x1, x1, lsl #2
  20100c: cb000440     	sub	x0, x2, x0, lsl #1
  201010: aa0103e2     	mov	x2, x1
  201014: 1100c000     	add	w0, w0, #48
  201018: 39005080     	strb	w0, [x4, #20]
  20101c: 54fffea8     	b.hi	0x200ff0 <print_elf+0xaf0>
  201020: 93407c60     	sxtw	x0, w3
  201024: 17fffe25     	b	0x2008b8 <print_elf+0x3b8>
  201028: 12000ee0     	and	w0, w23, #0xf
  20102c: d344fee1     	lsr	x1, x23, #4
  201030: 7100281f     	cmp	w0, #10
  201034: 11015c02     	add	w2, w0, #87
  201038: 1100c000     	add	w0, w0, #48
  20103c: 1a823000     	csel	w0, w0, w2, lo
  201040: 39015fe0     	strb	w0, [sp, #87]
  201044: b4005aa1     	cbz	x1, 0x201b98 <print_elf+0x1698>
  201048: 12000c20     	and	w0, w1, #0xf
  20104c: d348fee1     	lsr	x1, x23, #8
  201050: 7100281f     	cmp	w0, #10
  201054: 11015c02     	add	w2, w0, #87
  201058: 1100c000     	add	w0, w0, #48
  20105c: 1a823000     	csel	w0, w0, w2, lo
  201060: 39015be0     	strb	w0, [sp, #86]
  201064: b4005a41     	cbz	x1, 0x201bac <print_elf+0x16ac>
  201068: 12000c20     	and	w0, w1, #0xf
  20106c: d34cfee1     	lsr	x1, x23, #12
  201070: 7100281f     	cmp	w0, #10
  201074: 11015c02     	add	w2, w0, #87
  201078: 1100c000     	add	w0, w0, #48
  20107c: 1a823000     	csel	w0, w0, w2, lo
  201080: 390157e0     	strb	w0, [sp, #85]
  201084: b40059a1     	cbz	x1, 0x201bb8 <print_elf+0x16b8>
  201088: 12000c20     	and	w0, w1, #0xf
  20108c: d350fee1     	lsr	x1, x23, #16
  201090: 7100281f     	cmp	w0, #10
  201094: 11015c02     	add	w2, w0, #87
  201098: 1100c000     	add	w0, w0, #48
  20109c: 1a823000     	csel	w0, w0, w2, lo
  2010a0: 390153e0     	strb	w0, [sp, #84]
  2010a4: b4005981     	cbz	x1, 0x201bd4 <print_elf+0x16d4>
  2010a8: 12000c20     	and	w0, w1, #0xf
  2010ac: d354fee1     	lsr	x1, x23, #20
  2010b0: 7100281f     	cmp	w0, #10
  2010b4: 11015c02     	add	w2, w0, #87
  2010b8: 1100c000     	add	w0, w0, #48
  2010bc: 1a823000     	csel	w0, w0, w2, lo
  2010c0: 39014fe0     	strb	w0, [sp, #83]
  2010c4: b40058e1     	cbz	x1, 0x201be0 <print_elf+0x16e0>
  2010c8: 12000c20     	and	w0, w1, #0xf
  2010cc: d358fee1     	lsr	x1, x23, #24
  2010d0: 7100281f     	cmp	w0, #10
  2010d4: 11015c02     	add	w2, w0, #87
  2010d8: 1100c000     	add	w0, w0, #48
  2010dc: 1a823000     	csel	w0, w0, w2, lo
  2010e0: 39014be0     	strb	w0, [sp, #82]
  2010e4: b40058c1     	cbz	x1, 0x201bfc <print_elf+0x16fc>
  2010e8: 12000c20     	and	w0, w1, #0xf
  2010ec: d35cfee1     	lsr	x1, x23, #28
  2010f0: 7100281f     	cmp	w0, #10
  2010f4: 11015c02     	add	w2, w0, #87
  2010f8: 1100c000     	add	w0, w0, #48
  2010fc: 1a823000     	csel	w0, w0, w2, lo
  201100: 390147e0     	strb	w0, [sp, #81]
  201104: b4005821     	cbz	x1, 0x201c08 <print_elf+0x1708>
  201108: 12000c20     	and	w0, w1, #0xf
  20110c: d360fee1     	lsr	x1, x23, #32
  201110: 7100281f     	cmp	w0, #10
  201114: 11015c02     	add	w2, w0, #87
  201118: 1100c000     	add	w0, w0, #48
  20111c: 1a823000     	csel	w0, w0, w2, lo
  201120: 390143e0     	strb	w0, [sp, #80]
  201124: b40058c1     	cbz	x1, 0x201c3c <print_elf+0x173c>
  201128: 12000c20     	and	w0, w1, #0xf
  20112c: d364fee1     	lsr	x1, x23, #36
  201130: 7100281f     	cmp	w0, #10
  201134: 11015c02     	add	w2, w0, #87
  201138: 1100c000     	add	w0, w0, #48
  20113c: 1a823000     	csel	w0, w0, w2, lo
  201140: 39013fe0     	strb	w0, [sp, #79]
  201144: b4005861     	cbz	x1, 0x201c50 <print_elf+0x1750>
  201148: 12000c20     	and	w0, w1, #0xf
  20114c: d368fee1     	lsr	x1, x23, #40
  201150: 7100281f     	cmp	w0, #10
  201154: 11015c02     	add	w2, w0, #87
  201158: 1100c000     	add	w0, w0, #48
  20115c: 1a823000     	csel	w0, w0, w2, lo
  201160: 39013be0     	strb	w0, [sp, #78]
  201164: b40058c1     	cbz	x1, 0x201c7c <print_elf+0x177c>
  201168: 12000c20     	and	w0, w1, #0xf
  20116c: d36cfee1     	lsr	x1, x23, #44
  201170: 7100281f     	cmp	w0, #10
  201174: 11015c02     	add	w2, w0, #87
  201178: 1100c000     	add	w0, w0, #48
  20117c: 1a823000     	csel	w0, w0, w2, lo
  201180: 390137e0     	strb	w0, [sp, #77]
  201184: b4005821     	cbz	x1, 0x201c88 <print_elf+0x1788>
  201188: 12000c20     	and	w0, w1, #0xf
  20118c: d370fee1     	lsr	x1, x23, #48
  201190: 7100281f     	cmp	w0, #10
  201194: 11015c02     	add	w2, w0, #87
  201198: 1100c000     	add	w0, w0, #48
  20119c: 1a823000     	csel	w0, w0, w2, lo
  2011a0: 390133e0     	strb	w0, [sp, #76]
  2011a4: b40058e1     	cbz	x1, 0x201cc0 <print_elf+0x17c0>
  2011a8: 12000c20     	and	w0, w1, #0xf
  2011ac: d374fee1     	lsr	x1, x23, #52
  2011b0: 7100281f     	cmp	w0, #10
  2011b4: 11015c02     	add	w2, w0, #87
  2011b8: 1100c000     	add	w0, w0, #48
  2011bc: 1a823000     	csel	w0, w0, w2, lo
  2011c0: 39012fe0     	strb	w0, [sp, #75]
  2011c4: b4005781     	cbz	x1, 0x201cb4 <print_elf+0x17b4>
  2011c8: 12000c20     	and	w0, w1, #0xf
  2011cc: d378fee1     	lsr	x1, x23, #56
  2011d0: 7100281f     	cmp	w0, #10
  2011d4: 11015c02     	add	w2, w0, #87
  2011d8: 1100c000     	add	w0, w0, #48
  2011dc: 1a823000     	csel	w0, w0, w2, lo
  2011e0: 39012be0     	strb	w0, [sp, #74]
  2011e4: b40058e1     	cbz	x1, 0x201d00 <print_elf+0x1800>
  2011e8: 12000c20     	and	w0, w1, #0xf
  2011ec: d37cfef7     	lsr	x23, x23, #60
  2011f0: 7100281f     	cmp	w0, #10
  2011f4: 11015c01     	add	w1, w0, #87
  2011f8: 1100c000     	add	w0, w0, #48
  2011fc: 1a813000     	csel	w0, w0, w1, lo
  201200: 390127e0     	strb	w0, [sp, #73]
  201204: b4005797     	cbz	x23, 0x201cf4 <print_elf+0x17f4>
  201208: 710026ff     	cmp	w23, #9
  20120c: 1100c2e0     	add	w0, w23, #48
  201210: 52800001     	mov	w1, #0
  201214: 11015ef7     	add	w23, w23, #87
  201218: 1a8082e0     	csel	w0, w23, w0, hi
  20121c: 93407c37     	sxtw	x23, w1
  201220: 390123e0     	strb	w0, [sp, #72]
  201224: 17fffd69     	b	0x2007c8 <print_elf+0x2c8>
  201228: 52800601     	mov	w1, #48
  20122c: d2800260     	mov	x0, #19
  201230: 39016fe1     	strb	w1, [sp, #91]
  201234: 17fffe54     	b	0x200b84 <print_elf+0x684>
  201238: b0000000     	adrp	x0, 0x202000 <print_elf+0xd3c>
  20123c: 91224000     	add	x0, x0, #2192
  201240: 17fffd92     	b	0x200888 <print_elf+0x388>
  201244: 12000c01     	and	w1, w0, #0xf
  201248: d344fc02     	lsr	x2, x0, #4
  20124c: 7100283f     	cmp	w1, #10
  201250: 11015c23     	add	w3, w1, #87
  201254: 1100c021     	add	w1, w1, #48
  201258: 1a833021     	csel	w1, w1, w3, lo
  20125c: 39015fe1     	strb	w1, [sp, #87]
  201260: b4004de2     	cbz	x2, 0x201c1c <print_elf+0x171c>
  201264: 12000c41     	and	w1, w2, #0xf
  201268: d348fc02     	lsr	x2, x0, #8
  20126c: 7100283f     	cmp	w1, #10
  201270: 11015c23     	add	w3, w1, #87
  201274: 1100c021     	add	w1, w1, #48
  201278: 1a833021     	csel	w1, w1, w3, lo
  20127c: 39015be1     	strb	w1, [sp, #86]
  201280: b4004da2     	cbz	x2, 0x201c34 <print_elf+0x1734>
  201284: 12000c41     	and	w1, w2, #0xf
  201288: d34cfc02     	lsr	x2, x0, #12
  20128c: 7100283f     	cmp	w1, #10
  201290: 11015c23     	add	w3, w1, #87
  201294: 1100c021     	add	w1, w1, #48
  201298: 1a833021     	csel	w1, w1, w3, lo
  20129c: 390157e1     	strb	w1, [sp, #85]
  2012a0: b4004e22     	cbz	x2, 0x201c64 <print_elf+0x1764>
  2012a4: 12000c41     	and	w1, w2, #0xf
  2012a8: d350fc02     	lsr	x2, x0, #16
  2012ac: 7100283f     	cmp	w1, #10
  2012b0: 11015c23     	add	w3, w1, #87
  2012b4: 1100c021     	add	w1, w1, #48
  2012b8: 1a833021     	csel	w1, w1, w3, lo
  2012bc: 390153e1     	strb	w1, [sp, #84]
  2012c0: b4004ce2     	cbz	x2, 0x201c5c <print_elf+0x175c>
  2012c4: 12000c41     	and	w1, w2, #0xf
  2012c8: d354fc02     	lsr	x2, x0, #20
  2012cc: 7100283f     	cmp	w1, #10
  2012d0: 11015c23     	add	w3, w1, #87
  2012d4: 1100c021     	add	w1, w1, #48
  2012d8: 1a833021     	csel	w1, w1, w3, lo
  2012dc: 39014fe1     	strb	w1, [sp, #83]
  2012e0: b4004de2     	cbz	x2, 0x201c9c <print_elf+0x179c>
  2012e4: 12000c41     	and	w1, w2, #0xf
  2012e8: d358fc02     	lsr	x2, x0, #24
  2012ec: 7100283f     	cmp	w1, #10
  2012f0: 11015c23     	add	w3, w1, #87
  2012f4: 1100c021     	add	w1, w1, #48
  2012f8: 1a833021     	csel	w1, w1, w3, lo
  2012fc: 39014be1     	strb	w1, [sp, #82]
  201300: b4004ea2     	cbz	x2, 0x201cd4 <print_elf+0x17d4>
  201304: 12000c41     	and	w1, w2, #0xf
  201308: d35cfc02     	lsr	x2, x0, #28
  20130c: 7100283f     	cmp	w1, #10
  201310: 11015c23     	add	w3, w1, #87
  201314: 1100c021     	add	w1, w1, #48
  201318: 1a833021     	csel	w1, w1, w3, lo
  20131c: 390147e1     	strb	w1, [sp, #81]
  201320: b4004de2     	cbz	x2, 0x201cdc <print_elf+0x17dc>
  201324: 12000c41     	and	w1, w2, #0xf
  201328: d360fc02     	lsr	x2, x0, #32
  20132c: 7100283f     	cmp	w1, #10
  201330: 11015c23     	add	w3, w1, #87
  201334: 1100c021     	add	w1, w1, #48
  201338: 1a833021     	csel	w1, w1, w3, lo
  20133c: 390143e1     	strb	w1, [sp, #80]
  201340: b4004e62     	cbz	x2, 0x201d0c <print_elf+0x180c>
  201344: 12000c42     	and	w2, w2, #0xf
  201348: d364fc01     	lsr	x1, x0, #36
  20134c: 7100285f     	cmp	w2, #10
  201350: 11015c43     	add	w3, w2, #87
  201354: 1100c042     	add	w2, w2, #48
  201358: 1a833042     	csel	w2, w2, w3, lo
  20135c: 39013fe2     	strb	w2, [sp, #79]
  201360: b4004c61     	cbz	x1, 0x201cec <print_elf+0x17ec>
  201364: 12000c21     	and	w1, w1, #0xf
  201368: d368fc02     	lsr	x2, x0, #40
  20136c: 7100283f     	cmp	w1, #10
  201370: 11015c23     	add	w3, w1, #87
  201374: 1100c021     	add	w1, w1, #48
  201378: 1a833021     	csel	w1, w1, w3, lo
  20137c: 39013be1     	strb	w1, [sp, #78]
  201380: b4004e62     	cbz	x2, 0x201d4c <print_elf+0x184c>
  201384: 12000c41     	and	w1, w2, #0xf
  201388: d36cfc02     	lsr	x2, x0, #44
  20138c: 7100283f     	cmp	w1, #10
  201390: 11015c23     	add	w3, w1, #87
  201394: 1100c021     	add	w1, w1, #48
  201398: 1a833021     	csel	w1, w1, w3, lo
  20139c: 390137e1     	strb	w1, [sp, #77]
  2013a0: b4004d22     	cbz	x2, 0x201d44 <print_elf+0x1844>
  2013a4: 12000c42     	and	w2, w2, #0xf
  2013a8: d370fc01     	lsr	x1, x0, #48
  2013ac: 7100285f     	cmp	w2, #10
  2013b0: 11015c43     	add	w3, w2, #87
  2013b4: 1100c042     	add	w2, w2, #48
  2013b8: 1a833042     	csel	w2, w2, w3, lo
  2013bc: 390133e2     	strb	w2, [sp, #76]
  2013c0: b4004be1     	cbz	x1, 0x201d3c <print_elf+0x183c>
  2013c4: 12000c21     	and	w1, w1, #0xf
  2013c8: d374fc02     	lsr	x2, x0, #52
  2013cc: 7100283f     	cmp	w1, #10
  2013d0: 11015c23     	add	w3, w1, #87
  2013d4: 1100c021     	add	w1, w1, #48
  2013d8: 1a833021     	csel	w1, w1, w3, lo
  2013dc: 39012fe1     	strb	w1, [sp, #75]
  2013e0: b4004d62     	cbz	x2, 0x201d8c <print_elf+0x188c>
  2013e4: 12000c42     	and	w2, w2, #0xf
  2013e8: d378fc03     	lsr	x3, x0, #56
  2013ec: 7100285f     	cmp	w2, #10
  2013f0: 11015c41     	add	w1, w2, #87
  2013f4: 1100c042     	add	w2, w2, #48
  2013f8: 1a813041     	csel	w1, w2, w1, lo
  2013fc: 39012be1     	strb	w1, [sp, #74]
  201400: b4004c23     	cbz	x3, 0x201d84 <print_elf+0x1884>
  201404: 12000c61     	and	w1, w3, #0xf
  201408: d37cfc00     	lsr	x0, x0, #60
  20140c: 7100283f     	cmp	w1, #10
  201410: 11015c22     	add	w2, w1, #87
  201414: 1100c021     	add	w1, w1, #48
  201418: 1a823021     	csel	w1, w1, w2, lo
  20141c: 390127e1     	strb	w1, [sp, #73]
  201420: b4004ae0     	cbz	x0, 0x201d7c <print_elf+0x187c>
  201424: 7100241f     	cmp	w0, #9
  201428: 1100c001     	add	w1, w0, #48
  20142c: 11015c00     	add	w0, w0, #87
  201430: d2800017     	mov	x23, #0
  201434: 1a818000     	csel	w0, w0, w1, hi
  201438: 390123e0     	strb	w0, [sp, #72]
  20143c: 17fffd48     	b	0x20095c <print_elf+0x45c>
  201440: b0000000     	adrp	x0, 0x202000 <print_elf+0xf44>
  201444: 91222000     	add	x0, x0, #2184
  201448: 17fffd39     	b	0x20092c <print_elf+0x42c>
  20144c: b202e7e5     	mov	x5, #-3689348814741910324
  201450: aa1503e4     	mov	x4, x21
  201454: 52800283     	mov	w3, #20
  201458: f29999a5     	movk	x5, #52429
  20145c: d503201f     	nop
  201460: 9bc57c41     	umulh	x1, x2, x5
  201464: 51000463     	sub	w3, w3, #1
  201468: 7100007f     	cmp	w3, #0
  20146c: d1000484     	sub	x4, x4, #1
  201470: fa49c840     	ccmp	x2, #9, #0, gt
  201474: d343fc21     	lsr	x1, x1, #3
  201478: 8b010820     	add	x0, x1, x1, lsl #2
  20147c: cb000440     	sub	x0, x2, x0, lsl #1
  201480: aa0103e2     	mov	x2, x1
  201484: 1100c000     	add	w0, w0, #48
  201488: 39005080     	strb	w0, [x4, #20]
  20148c: 54fffea8     	b.hi	0x201460 <print_elf+0xf60>
  201490: 93407c60     	sxtw	x0, w3
  201494: 17fffda1     	b	0x200b18 <print_elf+0x618>
  201498: b202e7e5     	mov	x5, #-3689348814741910324
  20149c: aa1503e4     	mov	x4, x21
  2014a0: 52800283     	mov	w3, #20
  2014a4: f29999a5     	movk	x5, #52429
  2014a8: 9bc57c41     	umulh	x1, x2, x5
  2014ac: 51000463     	sub	w3, w3, #1
  2014b0: 7100007f     	cmp	w3, #0
  2014b4: d1000484     	sub	x4, x4, #1
  2014b8: fa49c840     	ccmp	x2, #9, #0, gt
  2014bc: d343fc21     	lsr	x1, x1, #3
  2014c0: 8b010820     	add	x0, x1, x1, lsl #2
  2014c4: cb000440     	sub	x0, x2, x0, lsl #1
  2014c8: aa0103e2     	mov	x2, x1
  2014cc: 1100c000     	add	w0, w0, #48
  2014d0: 39005080     	strb	w0, [x4, #20]
  2014d4: 54fffea8     	b.hi	0x2014a8 <print_elf+0xfa8>
  2014d8: 93407c60     	sxtw	x0, w3
  2014dc: 17fffd82     	b	0x200ae4 <print_elf+0x5e4>
  2014e0: b202e7e5     	mov	x5, #-3689348814741910324
  2014e4: aa1503e4     	mov	x4, x21
  2014e8: 52800283     	mov	w3, #20
  2014ec: f29999a5     	movk	x5, #52429
  2014f0: 9bc57c41     	umulh	x1, x2, x5
  2014f4: 51000463     	sub	w3, w3, #1
  2014f8: 7100007f     	cmp	w3, #0
  2014fc: d1000484     	sub	x4, x4, #1
  201500: fa49c840     	ccmp	x2, #9, #0, gt
  201504: d343fc21     	lsr	x1, x1, #3
  201508: 8b010820     	add	x0, x1, x1, lsl #2
  20150c: cb000440     	sub	x0, x2, x0, lsl #1
  201510: aa0103e2     	mov	x2, x1
  201514: 1100c000     	add	w0, w0, #48
  201518: 39005080     	strb	w0, [x4, #20]
  20151c: 54fffea8     	b.hi	0x2014f0 <print_elf+0xff0>
  201520: 93407c60     	sxtw	x0, w3
  201524: 17fffd63     	b	0x200ab0 <print_elf+0x5b0>
  201528: b202e7e5     	mov	x5, #-3689348814741910324
  20152c: aa1503e4     	mov	x4, x21
  201530: 52800283     	mov	w3, #20
  201534: f29999a5     	movk	x5, #52429
  201538: 9bc57c41     	umulh	x1, x2, x5
  20153c: 51000463     	sub	w3, w3, #1
  201540: 7100007f     	cmp	w3, #0
  201544: d1000484     	sub	x4, x4, #1
  201548: fa49c840     	ccmp	x2, #9, #0, gt
  20154c: d343fc21     	lsr	x1, x1, #3
  201550: 8b010820     	add	x0, x1, x1, lsl #2
  201554: cb000440     	sub	x0, x2, x0, lsl #1
  201558: aa0103e2     	mov	x2, x1
  20155c: 1100c000     	add	w0, w0, #48
  201560: 39005080     	strb	w0, [x4, #20]
  201564: 54fffea8     	b.hi	0x201538 <print_elf+0x1038>
  201568: 93407c60     	sxtw	x0, w3
  20156c: 17fffd44     	b	0x200a7c <print_elf+0x57c>
  201570: b202e7e5     	mov	x5, #-3689348814741910324
  201574: aa1503e4     	mov	x4, x21
  201578: 52800283     	mov	w3, #20
  20157c: f29999a5     	movk	x5, #52429
  201580: 9bc57c41     	umulh	x1, x2, x5
  201584: 51000463     	sub	w3, w3, #1
  201588: 7100007f     	cmp	w3, #0
  20158c: d1000484     	sub	x4, x4, #1
  201590: fa49c840     	ccmp	x2, #9, #0, gt
  201594: d343fc21     	lsr	x1, x1, #3
  201598: 8b010820     	add	x0, x1, x1, lsl #2
  20159c: cb000440     	sub	x0, x2, x0, lsl #1
  2015a0: aa0103e2     	mov	x2, x1
  2015a4: 1100c000     	add	w0, w0, #48
  2015a8: 39005080     	strb	w0, [x4, #20]
  2015ac: 54fffea8     	b.hi	0x201580 <print_elf+0x1080>
  2015b0: 93407c60     	sxtw	x0, w3
  2015b4: 17fffd25     	b	0x200a48 <print_elf+0x548>
  2015b8: 12000c00     	and	w0, w0, #0xf
  2015bc: d344fc22     	lsr	x2, x1, #4
  2015c0: 7100281f     	cmp	w0, #10
  2015c4: 11015c03     	add	w3, w0, #87
  2015c8: 1100c000     	add	w0, w0, #48
  2015cc: 1a833000     	csel	w0, w0, w3, lo
  2015d0: 39015fe0     	strb	w0, [sp, #87]
  2015d4: b4003282     	cbz	x2, 0x201c24 <print_elf+0x1724>
  2015d8: 12000c40     	and	w0, w2, #0xf
  2015dc: d348fc22     	lsr	x2, x1, #8
  2015e0: 7100281f     	cmp	w0, #10
  2015e4: 11015c03     	add	w3, w0, #87
  2015e8: 1100c000     	add	w0, w0, #48
  2015ec: 1a833000     	csel	w0, w0, w3, lo
  2015f0: 39015be0     	strb	w0, [sp, #86]
  2015f4: b40031c2     	cbz	x2, 0x201c2c <print_elf+0x172c>
  2015f8: 12000c40     	and	w0, w2, #0xf
  2015fc: d34cfc22     	lsr	x2, x1, #12
  201600: 7100281f     	cmp	w0, #10
  201604: 11015c03     	add	w3, w0, #87
  201608: 1100c000     	add	w0, w0, #48
  20160c: 1a833000     	csel	w0, w0, w3, lo
  201610: 390157e0     	strb	w0, [sp, #85]
  201614: b4003302     	cbz	x2, 0x201c74 <print_elf+0x1774>
  201618: 12000c40     	and	w0, w2, #0xf
  20161c: d350fc22     	lsr	x2, x1, #16
  201620: 7100281f     	cmp	w0, #10
  201624: 11015c03     	add	w3, w0, #87
  201628: 1100c000     	add	w0, w0, #48
  20162c: 1a833000     	csel	w0, w0, w3, lo
  201630: 390153e0     	strb	w0, [sp, #84]
  201634: b40031c2     	cbz	x2, 0x201c6c <print_elf+0x176c>
  201638: 12000c40     	and	w0, w2, #0xf
  20163c: d354fc22     	lsr	x2, x1, #20
  201640: 7100281f     	cmp	w0, #10
  201644: 11015c03     	add	w3, w0, #87
  201648: 1100c000     	add	w0, w0, #48
  20164c: 1a833000     	csel	w0, w0, w3, lo
  201650: 39014fe0     	strb	w0, [sp, #83]
  201654: b4003202     	cbz	x2, 0x201c94 <print_elf+0x1794>
  201658: 12000c40     	and	w0, w2, #0xf
  20165c: d358fc22     	lsr	x2, x1, #24
  201660: 7100281f     	cmp	w0, #10
  201664: 11015c03     	add	w3, w0, #87
  201668: 1100c000     	add	w0, w0, #48
  20166c: 1a833000     	csel	w0, w0, w3, lo
  201670: 39014be0     	strb	w0, [sp, #82]
  201674: b40032c2     	cbz	x2, 0x201ccc <print_elf+0x17cc>
  201678: 12000c42     	and	w2, w2, #0xf
  20167c: d35cfc20     	lsr	x0, x1, #28
  201680: 7100285f     	cmp	w2, #10
  201684: 11015c43     	add	w3, w2, #87
  201688: 1100c041     	add	w1, w2, #48
  20168c: 1a833021     	csel	w1, w1, w3, lo
  201690: 390147e1     	strb	w1, [sp, #81]
  201694: b4003080     	cbz	x0, 0x201ca4 <print_elf+0x17a4>
  201698: 12001c00     	and	w0, w0, #0xff
  20169c: d2800117     	mov	x23, #8
  2016a0: 11015c02     	add	w2, w0, #87
  2016a4: 1100c001     	add	w1, w0, #48
  2016a8: 7100281f     	cmp	w0, #10
  2016ac: 12001c42     	and	w2, w2, #0xff
  2016b0: 12001c20     	and	w0, w1, #0xff
  2016b4: 1a823000     	csel	w0, w0, w2, lo
  2016b8: 390143e0     	strb	w0, [sp, #80]
  2016bc: 17fffcd4     	b	0x200a0c <print_elf+0x50c>
  2016c0: b202e7e5     	mov	x5, #-3689348814741910324
  2016c4: aa1503e4     	mov	x4, x21
  2016c8: 52800283     	mov	w3, #20
  2016cc: f29999a5     	movk	x5, #52429
  2016d0: 9bc57c41     	umulh	x1, x2, x5
  2016d4: 51000463     	sub	w3, w3, #1
  2016d8: 7100007f     	cmp	w3, #0
  2016dc: d1000484     	sub	x4, x4, #1
  2016e0: fa49c840     	ccmp	x2, #9, #0, gt
  2016e4: d343fc21     	lsr	x1, x1, #3
  2016e8: 8b010820     	add	x0, x1, x1, lsl #2
  2016ec: cb000440     	sub	x0, x2, x0, lsl #1
  2016f0: aa0103e2     	mov	x2, x1
  2016f4: 1100c000     	add	w0, w0, #48
  2016f8: 39005080     	strb	w0, [x4, #20]
  2016fc: 54fffea8     	b.hi	0x2016d0 <print_elf+0x11d0>
  201700: 93407c60     	sxtw	x0, w3
  201704: 17fffcb4     	b	0x2009d4 <print_elf+0x4d4>
  201708: b202e7e5     	mov	x5, #-3689348814741910324
  20170c: aa1503e4     	mov	x4, x21
  201710: 52800283     	mov	w3, #20
  201714: f29999a5     	movk	x5, #52429
  201718: 9bc57c41     	umulh	x1, x2, x5
  20171c: 51000463     	sub	w3, w3, #1
  201720: 7100007f     	cmp	w3, #0
  201724: d1000484     	sub	x4, x4, #1
  201728: fa49c840     	ccmp	x2, #9, #0, gt
  20172c: d343fc21     	lsr	x1, x1, #3
  201730: 8b010820     	add	x0, x1, x1, lsl #2
  201734: cb000440     	sub	x0, x2, x0, lsl #1
  201738: aa0103e2     	mov	x2, x1
  20173c: 1100c000     	add	w0, w0, #48
  201740: 39005080     	strb	w0, [x4, #20]
  201744: 54fffea8     	b.hi	0x201718 <print_elf+0x1218>
  201748: 93407c60     	sxtw	x0, w3
  20174c: 17fffc93     	b	0x200998 <print_elf+0x498>
  201750: b0000000     	adrp	x0, 0x202000 <print_elf+0x1254>
  201754: 91224000     	add	x0, x0, #2192
  201758: 17fffd38     	b	0x200c38 <print_elf+0x738>
  20175c: b202e7e5     	mov	x5, #-3689348814741910324
  201760: aa1503e4     	mov	x4, x21
  201764: 52800283     	mov	w3, #20
  201768: f29999a5     	movk	x5, #52429
  20176c: d503201f     	nop
  201770: 9bc57c41     	umulh	x1, x2, x5
  201774: 51000463     	sub	w3, w3, #1
  201778: 7100007f     	cmp	w3, #0
  20177c: d1000484     	sub	x4, x4, #1
  201780: fa49c840     	ccmp	x2, #9, #0, gt
  201784: d343fc21     	lsr	x1, x1, #3
  201788: 8b010820     	add	x0, x1, x1, lsl #2
  20178c: cb000440     	sub	x0, x2, x0, lsl #1
  201790: aa0103e2     	mov	x2, x1
  201794: 1100c000     	add	w0, w0, #48
  201798: 39005080     	strb	w0, [x4, #20]
  20179c: 54fffea8     	b.hi	0x201770 <print_elf+0x1270>
  2017a0: 93407c60     	sxtw	x0, w3
  2017a4: 17fffdd0     	b	0x200ee4 <print_elf+0x9e4>
  2017a8: b202e7e5     	mov	x5, #-3689348814741910324
  2017ac: aa1503e4     	mov	x4, x21
  2017b0: 52800283     	mov	w3, #20
  2017b4: f29999a5     	movk	x5, #52429
  2017b8: 9bc57c41     	umulh	x1, x2, x5
  2017bc: 51000463     	sub	w3, w3, #1
  2017c0: 7100007f     	cmp	w3, #0
  2017c4: d1000484     	sub	x4, x4, #1
  2017c8: fa49c840     	ccmp	x2, #9, #0, gt
  2017cc: d343fc21     	lsr	x1, x1, #3
  2017d0: 8b010820     	add	x0, x1, x1, lsl #2
  2017d4: cb000440     	sub	x0, x2, x0, lsl #1
  2017d8: aa0103e2     	mov	x2, x1
  2017dc: 1100c000     	add	w0, w0, #48
  2017e0: 39005080     	strb	w0, [x4, #20]
  2017e4: 54fffea8     	b.hi	0x2017b8 <print_elf+0x12b8>
  2017e8: 93407c60     	sxtw	x0, w3
  2017ec: 17fffdb1     	b	0x200eb0 <print_elf+0x9b0>
  2017f0: b202e7e5     	mov	x5, #-3689348814741910324
  2017f4: aa1503e4     	mov	x4, x21
  2017f8: 52800283     	mov	w3, #20
  2017fc: f29999a5     	movk	x5, #52429
  201800: 9bc57c41     	umulh	x1, x2, x5
  201804: 51000463     	sub	w3, w3, #1
  201808: 7100007f     	cmp	w3, #0
  20180c: d1000484     	sub	x4, x4, #1
  201810: fa49c840     	ccmp	x2, #9, #0, gt
  201814: d343fc21     	lsr	x1, x1, #3
  201818: 8b010820     	add	x0, x1, x1, lsl #2
  20181c: cb000440     	sub	x0, x2, x0, lsl #1
  201820: aa0103e2     	mov	x2, x1
  201824: 1100c000     	add	w0, w0, #48
  201828: 39005080     	strb	w0, [x4, #20]
  20182c: 54fffea8     	b.hi	0x201800 <print_elf+0x1300>
  201830: 93407c60     	sxtw	x0, w3
  201834: 17fffd92     	b	0x200e7c <print_elf+0x97c>
  201838: b202e7e5     	mov	x5, #-3689348814741910324
  20183c: aa1503e4     	mov	x4, x21
  201840: 52800283     	mov	w3, #20
  201844: f29999a5     	movk	x5, #52429
  201848: 9bc57c41     	umulh	x1, x2, x5
  20184c: 51000463     	sub	w3, w3, #1
  201850: 7100007f     	cmp	w3, #0
  201854: d1000484     	sub	x4, x4, #1
  201858: fa49c840     	ccmp	x2, #9, #0, gt
  20185c: d343fc21     	lsr	x1, x1, #3
  201860: 8b010820     	add	x0, x1, x1, lsl #2
  201864: cb000440     	sub	x0, x2, x0, lsl #1
  201868: aa0103e2     	mov	x2, x1
  20186c: 1100c000     	add	w0, w0, #48
  201870: 39005080     	strb	w0, [x4, #20]
  201874: 54fffea8     	b.hi	0x201848 <print_elf+0x1348>
  201878: 93407c60     	sxtw	x0, w3
  20187c: 17fffd73     	b	0x200e48 <print_elf+0x948>
  201880: b202e7e5     	mov	x5, #-3689348814741910324
  201884: aa1503e4     	mov	x4, x21
  201888: 52800283     	mov	w3, #20
  20188c: f29999a5     	movk	x5, #52429
  201890: 9bc57c41     	umulh	x1, x2, x5
  201894: 51000463     	sub	w3, w3, #1
  201898: 7100007f     	cmp	w3, #0
  20189c: d1000484     	sub	x4, x4, #1
  2018a0: fa49c840     	ccmp	x2, #9, #0, gt
  2018a4: d343fc21     	lsr	x1, x1, #3
  2018a8: 8b010820     	add	x0, x1, x1, lsl #2
  2018ac: cb000440     	sub	x0, x2, x0, lsl #1
  2018b0: aa0103e2     	mov	x2, x1
  2018b4: 1100c000     	add	w0, w0, #48
  2018b8: 39005080     	strb	w0, [x4, #20]
  2018bc: 54fffea8     	b.hi	0x201890 <print_elf+0x1390>
  2018c0: 93407c60     	sxtw	x0, w3
  2018c4: 17fffd52     	b	0x200e0c <print_elf+0x90c>
  2018c8: 12000c00     	and	w0, w0, #0xf
  2018cc: d344fc22     	lsr	x2, x1, #4
  2018d0: 7100281f     	cmp	w0, #10
  2018d4: 11015c03     	add	w3, w0, #87
  2018d8: 1100c000     	add	w0, w0, #48
  2018dc: 1a833000     	csel	w0, w0, w3, lo
  2018e0: 39015fe0     	strb	w0, [sp, #87]
  2018e4: b4001e42     	cbz	x2, 0x201cac <print_elf+0x17ac>
  2018e8: 12000c40     	and	w0, w2, #0xf
  2018ec: d348fc22     	lsr	x2, x1, #8
  2018f0: 7100281f     	cmp	w0, #10
  2018f4: 11015c03     	add	w3, w0, #87
  2018f8: 1100c000     	add	w0, w0, #48
  2018fc: 1a833000     	csel	w0, w0, w3, lo
  201900: 39015be0     	strb	w0, [sp, #86]
  201904: b4002102     	cbz	x2, 0x201d24 <print_elf+0x1824>
  201908: 12000c42     	and	w2, w2, #0xf
  20190c: d34cfc20     	lsr	x0, x1, #12
  201910: 7100285f     	cmp	w2, #10
  201914: 11015c43     	add	w3, w2, #87
  201918: 1100c042     	add	w2, w2, #48
  20191c: 1a833042     	csel	w2, w2, w3, lo
  201920: 390157e2     	strb	w2, [sp, #85]
  201924: b4002040     	cbz	x0, 0x201d2c <print_elf+0x182c>
  201928: 12000c00     	and	w0, w0, #0xf
  20192c: d350fc22     	lsr	x2, x1, #16
  201930: 7100281f     	cmp	w0, #10
  201934: 11015c03     	add	w3, w0, #87
  201938: 1100c000     	add	w0, w0, #48
  20193c: 1a833000     	csel	w0, w0, w3, lo
  201940: 390153e0     	strb	w0, [sp, #84]
  201944: b4001f82     	cbz	x2, 0x201d34 <print_elf+0x1834>
  201948: 12000c40     	and	w0, w2, #0xf
  20194c: d354fc22     	lsr	x2, x1, #20
  201950: 7100281f     	cmp	w0, #10
  201954: 11015c03     	add	w3, w0, #87
  201958: 1100c000     	add	w0, w0, #48
  20195c: 1a833000     	csel	w0, w0, w3, lo
  201960: 39014fe0     	strb	w0, [sp, #83]
  201964: b4002002     	cbz	x2, 0x201d64 <print_elf+0x1864>
  201968: 12000c42     	and	w2, w2, #0xf
  20196c: d358fc20     	lsr	x0, x1, #24
  201970: 7100285f     	cmp	w2, #10
  201974: 11015c43     	add	w3, w2, #87
  201978: 1100c042     	add	w2, w2, #48
  20197c: 1a833042     	csel	w2, w2, w3, lo
  201980: 39014be2     	strb	w2, [sp, #82]
  201984: b4001ec0     	cbz	x0, 0x201d5c <print_elf+0x185c>
  201988: 12000c00     	and	w0, w0, #0xf
  20198c: d35cfc21     	lsr	x1, x1, #28
  201990: 7100281f     	cmp	w0, #10
  201994: 11015c02     	add	w2, w0, #87
  201998: 1100c000     	add	w0, w0, #48
  20199c: 1a823000     	csel	w0, w0, w2, lo
  2019a0: 390147e0     	strb	w0, [sp, #81]
  2019a4: b4001fc1     	cbz	x1, 0x201d9c <print_elf+0x189c>
  2019a8: 12001c21     	and	w1, w1, #0xff
  2019ac: d2800114     	mov	x20, #8
  2019b0: 1100c020     	add	w0, w1, #48
  2019b4: 11015c22     	add	w2, w1, #87
  2019b8: 7100283f     	cmp	w1, #10
  2019bc: 12001c00     	and	w0, w0, #0xff
  2019c0: 12001c41     	and	w1, w2, #0xff
  2019c4: 1a813000     	csel	w0, w0, w1, lo
  2019c8: 390143e0     	strb	w0, [sp, #80]
  2019cc: 17fffd01     	b	0x200dd0 <print_elf+0x8d0>
  2019d0: b202e7e5     	mov	x5, #-3689348814741910324
  2019d4: aa1503e4     	mov	x4, x21
  2019d8: 52800283     	mov	w3, #20
  2019dc: f29999a5     	movk	x5, #52429
  2019e0: 9bc57c41     	umulh	x1, x2, x5
  2019e4: 51000463     	sub	w3, w3, #1
  2019e8: 7100007f     	cmp	w3, #0
  2019ec: d1000484     	sub	x4, x4, #1
  2019f0: fa49c840     	ccmp	x2, #9, #0, gt
  2019f4: d343fc21     	lsr	x1, x1, #3
  2019f8: 8b010820     	add	x0, x1, x1, lsl #2
  2019fc: cb000440     	sub	x0, x2, x0, lsl #1
  201a00: aa0103e2     	mov	x2, x1
  201a04: 1100c000     	add	w0, w0, #48
  201a08: 39005080     	strb	w0, [x4, #20]
  201a0c: 54fffea8     	b.hi	0x2019e0 <print_elf+0x14e0>
  201a10: 93407c60     	sxtw	x0, w3
  201a14: 17fffce1     	b	0x200d98 <print_elf+0x898>
  201a18: b202e7e5     	mov	x5, #-3689348814741910324
  201a1c: aa1503e4     	mov	x4, x21
  201a20: 52800283     	mov	w3, #20
  201a24: f29999a5     	movk	x5, #52429
  201a28: 9bc57c41     	umulh	x1, x2, x5
  201a2c: 51000463     	sub	w3, w3, #1
  201a30: 7100007f     	cmp	w3, #0
  201a34: d1000484     	sub	x4, x4, #1
  201a38: fa49c840     	ccmp	x2, #9, #0, gt
  201a3c: d343fc21     	lsr	x1, x1, #3
  201a40: 8b010820     	add	x0, x1, x1, lsl #2
  201a44: cb000440     	sub	x0, x2, x0, lsl #1
  201a48: aa0103e2     	mov	x2, x1
  201a4c: 1100c000     	add	w0, w0, #48
  201a50: 39005080     	strb	w0, [x4, #20]
  201a54: 54fffea8     	b.hi	0x201a28 <print_elf+0x1528>
  201a58: 93407c60     	sxtw	x0, w3
  201a5c: 17fffcc0     	b	0x200d5c <print_elf+0x85c>
  201a60: 12000c00     	and	w0, w0, #0xf
  201a64: d344fc22     	lsr	x2, x1, #4
  201a68: 7100281f     	cmp	w0, #10
  201a6c: 11015c03     	add	w3, w0, #87
  201a70: 1100c000     	add	w0, w0, #48
  201a74: 1a833000     	csel	w0, w0, w3, lo
  201a78: 39015fe0     	strb	w0, [sp, #87]
  201a7c: b4001342     	cbz	x2, 0x201ce4 <print_elf+0x17e4>
  201a80: 12000c40     	and	w0, w2, #0xf
  201a84: d348fc22     	lsr	x2, x1, #8
  201a88: 7100281f     	cmp	w0, #10
  201a8c: 11015c03     	add	w3, w0, #87
  201a90: 1100c000     	add	w0, w0, #48
  201a94: 1a833000     	csel	w0, w0, w3, lo
  201a98: 39015be0     	strb	w0, [sp, #86]
  201a9c: b40013c2     	cbz	x2, 0x201d14 <print_elf+0x1814>
  201aa0: 12000c42     	and	w2, w2, #0xf
  201aa4: d34cfc20     	lsr	x0, x1, #12
  201aa8: 7100285f     	cmp	w2, #10
  201aac: 11015c43     	add	w3, w2, #87
  201ab0: 1100c042     	add	w2, w2, #48
  201ab4: 1a833042     	csel	w2, w2, w3, lo
  201ab8: 390157e2     	strb	w2, [sp, #85]
  201abc: b4001300     	cbz	x0, 0x201d1c <print_elf+0x181c>
  201ac0: 12000c00     	and	w0, w0, #0xf
  201ac4: d350fc22     	lsr	x2, x1, #16
  201ac8: 7100281f     	cmp	w0, #10
  201acc: 11015c03     	add	w3, w0, #87
  201ad0: 1100c000     	add	w0, w0, #48
  201ad4: 1a833000     	csel	w0, w0, w3, lo
  201ad8: 390153e0     	strb	w0, [sp, #84]
  201adc: b40013c2     	cbz	x2, 0x201d54 <print_elf+0x1854>
  201ae0: 12000c40     	and	w0, w2, #0xf
  201ae4: d354fc22     	lsr	x2, x1, #20
  201ae8: 7100281f     	cmp	w0, #10
  201aec: 11015c03     	add	w3, w0, #87
  201af0: 1100c000     	add	w0, w0, #48
  201af4: 1a833000     	csel	w0, w0, w3, lo
  201af8: 39014fe0     	strb	w0, [sp, #83]
  201afc: b40013c2     	cbz	x2, 0x201d74 <print_elf+0x1874>
  201b00: 12000c42     	and	w2, w2, #0xf
  201b04: d358fc20     	lsr	x0, x1, #24
  201b08: 7100285f     	cmp	w2, #10
  201b0c: 11015c43     	add	w3, w2, #87
  201b10: 1100c042     	add	w2, w2, #48
  201b14: 1a833042     	csel	w2, w2, w3, lo
  201b18: 39014be2     	strb	w2, [sp, #82]
  201b1c: b4001280     	cbz	x0, 0x201d6c <print_elf+0x186c>
  201b20: 12000c00     	and	w0, w0, #0xf
  201b24: d35cfc21     	lsr	x1, x1, #28
  201b28: 7100281f     	cmp	w0, #10
  201b2c: 11015c02     	add	w2, w0, #87
  201b30: 1100c000     	add	w0, w0, #48
  201b34: 1a823000     	csel	w0, w0, w2, lo
  201b38: 390147e0     	strb	w0, [sp, #81]
  201b3c: b40012c1     	cbz	x1, 0x201d94 <print_elf+0x1894>
  201b40: 12001c21     	and	w1, w1, #0xff
  201b44: d2800114     	mov	x20, #8
  201b48: 1100c020     	add	w0, w1, #48
  201b4c: 11015c22     	add	w2, w1, #87
  201b50: 7100283f     	cmp	w1, #10
  201b54: 12001c00     	and	w0, w0, #0xff
  201b58: 12001c41     	and	w1, w2, #0xff
  201b5c: 1a813000     	csel	w0, w0, w1, lo
  201b60: 390143e0     	strb	w0, [sp, #80]
  201b64: 17fffc6d     	b	0x200d18 <print_elf+0x818>
  201b68: 528001f8     	mov	w24, #15
  201b6c: 17fffb05     	b	0x200780 <print_elf+0x280>
  201b70: 528001d8     	mov	w24, #14
  201b74: 17fffb03     	b	0x200780 <print_elf+0x280>
  201b78: 52800198     	mov	w24, #12
  201b7c: 17fffb01     	b	0x200780 <print_elf+0x280>
  201b80: 52800178     	mov	w24, #11
  201b84: 17fffaff     	b	0x200780 <print_elf+0x280>
  201b88: 52800158     	mov	w24, #10
  201b8c: 17fffafd     	b	0x200780 <print_elf+0x280>
  201b90: 52800138     	mov	w24, #9
  201b94: 17fffafb     	b	0x200780 <print_elf+0x280>
  201b98: 528001e1     	mov	w1, #15
  201b9c: 93407c37     	sxtw	x23, w1
  201ba0: 17fffb0a     	b	0x2007c8 <print_elf+0x2c8>
  201ba4: 52800118     	mov	w24, #8
  201ba8: 17fffaf6     	b	0x200780 <print_elf+0x280>
  201bac: 528001c1     	mov	w1, #14
  201bb0: 93407c37     	sxtw	x23, w1
  201bb4: 17fffb05     	b	0x2007c8 <print_elf+0x2c8>
  201bb8: 528001a1     	mov	w1, #13
  201bbc: 93407c37     	sxtw	x23, w1
  201bc0: 17fffb02     	b	0x2007c8 <print_elf+0x2c8>
  201bc4: 528000f8     	mov	w24, #7
  201bc8: 17fffaee     	b	0x200780 <print_elf+0x280>
  201bcc: 528000d8     	mov	w24, #6
  201bd0: 17fffaec     	b	0x200780 <print_elf+0x280>
  201bd4: 52800181     	mov	w1, #12
  201bd8: 93407c37     	sxtw	x23, w1
  201bdc: 17fffafb     	b	0x2007c8 <print_elf+0x2c8>
  201be0: 52800161     	mov	w1, #11
  201be4: 93407c37     	sxtw	x23, w1
  201be8: 17fffaf8     	b	0x2007c8 <print_elf+0x2c8>
  201bec: 528000b8     	mov	w24, #5
  201bf0: 17fffae4     	b	0x200780 <print_elf+0x280>
  201bf4: 52800098     	mov	w24, #4
  201bf8: 17fffae2     	b	0x200780 <print_elf+0x280>
  201bfc: 52800141     	mov	w1, #10
  201c00: 93407c37     	sxtw	x23, w1
  201c04: 17fffaf1     	b	0x2007c8 <print_elf+0x2c8>
  201c08: 52800121     	mov	w1, #9
  201c0c: 93407c37     	sxtw	x23, w1
  201c10: 17fffaee     	b	0x2007c8 <print_elf+0x2c8>
  201c14: 52800078     	mov	w24, #3
  201c18: 17fffada     	b	0x200780 <print_elf+0x280>
  201c1c: d28001f7     	mov	x23, #15
  201c20: 17fffb4f     	b	0x20095c <print_elf+0x45c>
  201c24: d28001f7     	mov	x23, #15
  201c28: 17fffb79     	b	0x200a0c <print_elf+0x50c>
  201c2c: d28001d7     	mov	x23, #14
  201c30: 17fffb77     	b	0x200a0c <print_elf+0x50c>
  201c34: d28001d7     	mov	x23, #14
  201c38: 17fffb49     	b	0x20095c <print_elf+0x45c>
  201c3c: 52800101     	mov	w1, #8
  201c40: 93407c37     	sxtw	x23, w1
  201c44: 17fffae1     	b	0x2007c8 <print_elf+0x2c8>
  201c48: 52800038     	mov	w24, #1
  201c4c: 17fffacd     	b	0x200780 <print_elf+0x280>
  201c50: 528000e1     	mov	w1, #7
  201c54: 93407c37     	sxtw	x23, w1
  201c58: 17fffadc     	b	0x2007c8 <print_elf+0x2c8>
  201c5c: d2800197     	mov	x23, #12
  201c60: 17fffb3f     	b	0x20095c <print_elf+0x45c>
  201c64: d28001b7     	mov	x23, #13
  201c68: 17fffb3d     	b	0x20095c <print_elf+0x45c>
  201c6c: d2800197     	mov	x23, #12
  201c70: 17fffb67     	b	0x200a0c <print_elf+0x50c>
  201c74: d28001b7     	mov	x23, #13
  201c78: 17fffb65     	b	0x200a0c <print_elf+0x50c>
  201c7c: 528000c1     	mov	w1, #6
  201c80: 93407c37     	sxtw	x23, w1
  201c84: 17fffad1     	b	0x2007c8 <print_elf+0x2c8>
  201c88: 528000a1     	mov	w1, #5
  201c8c: 93407c37     	sxtw	x23, w1
  201c90: 17ffface     	b	0x2007c8 <print_elf+0x2c8>
  201c94: d2800177     	mov	x23, #11
  201c98: 17fffb5d     	b	0x200a0c <print_elf+0x50c>
  201c9c: d2800177     	mov	x23, #11
  201ca0: 17fffb2f     	b	0x20095c <print_elf+0x45c>
  201ca4: d2800137     	mov	x23, #9
  201ca8: 17fffb59     	b	0x200a0c <print_elf+0x50c>
  201cac: d28001f4     	mov	x20, #15
  201cb0: 17fffc48     	b	0x200dd0 <print_elf+0x8d0>
  201cb4: 52800061     	mov	w1, #3
  201cb8: 93407c37     	sxtw	x23, w1
  201cbc: 17fffac3     	b	0x2007c8 <print_elf+0x2c8>
  201cc0: 52800081     	mov	w1, #4
  201cc4: 93407c37     	sxtw	x23, w1
  201cc8: 17fffac0     	b	0x2007c8 <print_elf+0x2c8>
  201ccc: d2800157     	mov	x23, #10
  201cd0: 17fffb4f     	b	0x200a0c <print_elf+0x50c>
  201cd4: d2800157     	mov	x23, #10
  201cd8: 17fffb21     	b	0x20095c <print_elf+0x45c>
  201cdc: d2800137     	mov	x23, #9
  201ce0: 17fffb1f     	b	0x20095c <print_elf+0x45c>
  201ce4: d28001f4     	mov	x20, #15
  201ce8: 17fffc0c     	b	0x200d18 <print_elf+0x818>
  201cec: d28000f7     	mov	x23, #7
  201cf0: 17fffb1b     	b	0x20095c <print_elf+0x45c>
  201cf4: 52800021     	mov	w1, #1
  201cf8: 93407c37     	sxtw	x23, w1
  201cfc: 17fffab3     	b	0x2007c8 <print_elf+0x2c8>
  201d00: 52800041     	mov	w1, #2
  201d04: 93407c37     	sxtw	x23, w1
  201d08: 17fffab0     	b	0x2007c8 <print_elf+0x2c8>
  201d0c: d2800117     	mov	x23, #8
  201d10: 17fffb13     	b	0x20095c <print_elf+0x45c>
  201d14: d28001d4     	mov	x20, #14
  201d18: 17fffc00     	b	0x200d18 <print_elf+0x818>
  201d1c: d28001b4     	mov	x20, #13
  201d20: 17fffbfe     	b	0x200d18 <print_elf+0x818>
  201d24: d28001d4     	mov	x20, #14
  201d28: 17fffc2a     	b	0x200dd0 <print_elf+0x8d0>
  201d2c: d28001b4     	mov	x20, #13
  201d30: 17fffc28     	b	0x200dd0 <print_elf+0x8d0>
  201d34: d2800194     	mov	x20, #12
  201d38: 17fffc26     	b	0x200dd0 <print_elf+0x8d0>
  201d3c: d2800097     	mov	x23, #4
  201d40: 17fffb07     	b	0x20095c <print_elf+0x45c>
  201d44: d28000b7     	mov	x23, #5
  201d48: 17fffb05     	b	0x20095c <print_elf+0x45c>
  201d4c: d28000d7     	mov	x23, #6
  201d50: 17fffb03     	b	0x20095c <print_elf+0x45c>
  201d54: d2800194     	mov	x20, #12
  201d58: 17fffbf0     	b	0x200d18 <print_elf+0x818>
  201d5c: d2800154     	mov	x20, #10
  201d60: 17fffc1c     	b	0x200dd0 <print_elf+0x8d0>
  201d64: d2800174     	mov	x20, #11
  201d68: 17fffc1a     	b	0x200dd0 <print_elf+0x8d0>
  201d6c: d2800154     	mov	x20, #10
  201d70: 17fffbea     	b	0x200d18 <print_elf+0x818>
  201d74: d2800174     	mov	x20, #11
  201d78: 17fffbe8     	b	0x200d18 <print_elf+0x818>
  201d7c: d2800037     	mov	x23, #1
  201d80: 17fffaf7     	b	0x20095c <print_elf+0x45c>
  201d84: d2800057     	mov	x23, #2
  201d88: 17fffaf5     	b	0x20095c <print_elf+0x45c>
  201d8c: d2800077     	mov	x23, #3
  201d90: 17fffaf3     	b	0x20095c <print_elf+0x45c>
  201d94: d2800134     	mov	x20, #9
  201d98: 17fffbe0     	b	0x200d18 <print_elf+0x818>
  201d9c: d2800134     	mov	x20, #9
  201da0: 17fffc0c     	b	0x200dd0 <print_elf+0x8d0>
  201da4: d503201f     	nop
  201da8: d503201f     	nop
  201dac: d503201f     	nop

0000000000201db0 <custom_memcpy>:
  201db0: b4000222     	cbz	x2, 0x201df4 <custom_memcpy+0x44>
  201db4: d1000443     	sub	x3, x2, #1
  201db8: f100387f     	cmp	x3, #14
  201dbc: 54000c49     	b.ls	0x201f44 <custom_memcpy+0x194>
  201dc0: aa010005     	orr	x5, x0, x1
  201dc4: 91000424     	add	x4, x1, #1
  201dc8: cb040004     	sub	x4, x0, x4
  201dcc: d2800003     	mov	x3, #0
  201dd0: f2400cbf     	tst	x5, #0xf
  201dd4: fa4e0880     	ccmp	x4, #14, #0, eq
  201dd8: 54000108     	b.hi	0x201df8 <custom_memcpy+0x48>
  201ddc: d503201f     	nop
  201de0: 38636824     	ldrb	w4, [x1, x3]
  201de4: 38236804     	strb	w4, [x0, x3]
  201de8: 91000463     	add	x3, x3, #1
  201dec: eb03005f     	cmp	x2, x3
  201df0: 54ffff81     	b.ne	0x201de0 <custom_memcpy+0x30>
  201df4: d65f03c0     	ret
  201df8: 927cec44     	and	x4, x2, #0xfffffffffffffff0
  201dfc: d503201f     	nop
  201e00: 3ce36820     	ldr	q0, [x1, x3]
  201e04: 3ca36800     	str	q0, [x0, x3]
  201e08: 91004063     	add	x3, x3, #16
  201e0c: eb03009f     	cmp	x4, x3
  201e10: 54ffff81     	b.ne	0x201e00 <custom_memcpy+0x50>
  201e14: f2400c5f     	tst	x2, #0xf
  201e18: 927cec43     	and	x3, x2, #0xfffffffffffffff0
  201e1c: 54fffec0     	b.eq	0x201df4 <custom_memcpy+0x44>
  201e20: 38636825     	ldrb	w5, [x1, x3]
  201e24: 91000464     	add	x4, x3, #1
  201e28: 38236805     	strb	w5, [x0, x3]
  201e2c: eb04005f     	cmp	x2, x4
  201e30: 54fffe29     	b.ls	0x201df4 <custom_memcpy+0x44>
  201e34: 38646826     	ldrb	w6, [x1, x4]
  201e38: 91000865     	add	x5, x3, #2
  201e3c: 38246806     	strb	w6, [x0, x4]
  201e40: eb05005f     	cmp	x2, x5
  201e44: 54fffd89     	b.ls	0x201df4 <custom_memcpy+0x44>
  201e48: 38656826     	ldrb	w6, [x1, x5]
  201e4c: 91000c64     	add	x4, x3, #3
  201e50: 38256806     	strb	w6, [x0, x5]
  201e54: eb04005f     	cmp	x2, x4
  201e58: 54fffce9     	b.ls	0x201df4 <custom_memcpy+0x44>
  201e5c: 38646826     	ldrb	w6, [x1, x4]
  201e60: 91001065     	add	x5, x3, #4
  201e64: 38246806     	strb	w6, [x0, x4]
  201e68: eb05005f     	cmp	x2, x5
  201e6c: 54fffc49     	b.ls	0x201df4 <custom_memcpy+0x44>
  201e70: 38656826     	ldrb	w6, [x1, x5]
  201e74: 91001464     	add	x4, x3, #5
  201e78: 38256806     	strb	w6, [x0, x5]
  201e7c: eb04005f     	cmp	x2, x4
  201e80: 54fffba9     	b.ls	0x201df4 <custom_memcpy+0x44>
  201e84: 38646826     	ldrb	w6, [x1, x4]
  201e88: 91001865     	add	x5, x3, #6
  201e8c: 38246806     	strb	w6, [x0, x4]
  201e90: eb05005f     	cmp	x2, x5
  201e94: 54fffb09     	b.ls	0x201df4 <custom_memcpy+0x44>
  201e98: 38656826     	ldrb	w6, [x1, x5]
  201e9c: 91001c64     	add	x4, x3, #7
  201ea0: 38256806     	strb	w6, [x0, x5]
  201ea4: eb04005f     	cmp	x2, x4
  201ea8: 54fffa69     	b.ls	0x201df4 <custom_memcpy+0x44>
  201eac: 38646826     	ldrb	w6, [x1, x4]
  201eb0: 91002065     	add	x5, x3, #8
  201eb4: 38246806     	strb	w6, [x0, x4]
  201eb8: eb05005f     	cmp	x2, x5
  201ebc: 54fff9c9     	b.ls	0x201df4 <custom_memcpy+0x44>
  201ec0: 38656826     	ldrb	w6, [x1, x5]
  201ec4: 91002464     	add	x4, x3, #9
  201ec8: 38256806     	strb	w6, [x0, x5]
  201ecc: eb04005f     	cmp	x2, x4
  201ed0: 54fff929     	b.ls	0x201df4 <custom_memcpy+0x44>
  201ed4: 38646826     	ldrb	w6, [x1, x4]
  201ed8: 91002865     	add	x5, x3, #10
  201edc: 38246806     	strb	w6, [x0, x4]
  201ee0: eb05005f     	cmp	x2, x5
  201ee4: 54fff889     	b.ls	0x201df4 <custom_memcpy+0x44>
  201ee8: 38656826     	ldrb	w6, [x1, x5]
  201eec: 91002c64     	add	x4, x3, #11
  201ef0: 38256806     	strb	w6, [x0, x5]
  201ef4: eb04005f     	cmp	x2, x4
  201ef8: 54fff7e9     	b.ls	0x201df4 <custom_memcpy+0x44>
  201efc: 38646826     	ldrb	w6, [x1, x4]
  201f00: 91003065     	add	x5, x3, #12
  201f04: 38246806     	strb	w6, [x0, x4]
  201f08: eb05005f     	cmp	x2, x5
  201f0c: 54fff749     	b.ls	0x201df4 <custom_memcpy+0x44>
  201f10: 38656826     	ldrb	w6, [x1, x5]
  201f14: 91003464     	add	x4, x3, #13
  201f18: 38256806     	strb	w6, [x0, x5]
  201f1c: eb04005f     	cmp	x2, x4
  201f20: 54fff6a9     	b.ls	0x201df4 <custom_memcpy+0x44>
  201f24: 38646825     	ldrb	w5, [x1, x4]
  201f28: 91003863     	add	x3, x3, #14
  201f2c: 38246805     	strb	w5, [x0, x4]
  201f30: eb03005f     	cmp	x2, x3
  201f34: 54fff609     	b.ls	0x201df4 <custom_memcpy+0x44>
  201f38: 38636821     	ldrb	w1, [x1, x3]
  201f3c: 38236801     	strb	w1, [x0, x3]
  201f40: d65f03c0     	ret
  201f44: d2800003     	mov	x3, #0
  201f48: 38636824     	ldrb	w4, [x1, x3]
  201f4c: 38236804     	strb	w4, [x0, x3]
  201f50: 91000463     	add	x3, x3, #1
  201f54: eb03005f     	cmp	x2, x3
  201f58: 54fff441     	b.ne	0x201de0 <custom_memcpy+0x30>
  201f5c: 17ffffa6     	b	0x201df4 <custom_memcpy+0x44>

0000000000201f60 <custom_memset>:
  201f60: b4000982     	cbz	x2, 0x202090 <custom_memset+0x130>
  201f64: cb0003e6     	neg	x6, x0
  201f68: d28002e7     	mov	x7, #23
  201f6c: 92400cc3     	and	x3, x6, #0xf
  201f70: d1000445     	sub	x5, x2, #1
  201f74: 91003c64     	add	x4, x3, #15
  201f78: 12001c21     	and	w1, w1, #0xff
  201f7c: eb07009f     	cmp	x4, x7
  201f80: 1e270020     	fmov	s0, w1
  201f84: 9a872084     	csel	x4, x4, x7, hs
  201f88: eb0400bf     	cmp	x5, x4
  201f8c: 54000883     	b.lo	0x20209c <custom_memset+0x13c>
  201f90: b4000963     	cbz	x3, 0x2020bc <custom_memset+0x15c>
  201f94: 3d000000     	str	b0, [x0]
  201f98: f27f08df     	tst	x6, #0xe
  201f9c: 54000840     	b.eq	0x2020a4 <custom_memset+0x144>
  201fa0: 3d000400     	str	b0, [x0, #1]
  201fa4: f100087f     	cmp	x3, #2
  201fa8: 54000829     	b.ls	0x2020ac <custom_memset+0x14c>
  201fac: 3d000800     	str	b0, [x0, #2]
  201fb0: f27e04df     	tst	x6, #0xc
  201fb4: 54000800     	b.eq	0x2020b4 <custom_memset+0x154>
  201fb8: 3d000c00     	str	b0, [x0, #3]
  201fbc: f100107f     	cmp	x3, #4
  201fc0: 540006a9     	b.ls	0x202094 <custom_memset+0x134>
  201fc4: 3d001000     	str	b0, [x0, #4]
  201fc8: f100147f     	cmp	x3, #5
  201fcc: 540003e0     	b.eq	0x202048 <custom_memset+0xe8>
  201fd0: 3d001400     	str	b0, [x0, #5]
  201fd4: f100187f     	cmp	x3, #6
  201fd8: 54000380     	b.eq	0x202048 <custom_memset+0xe8>
  201fdc: 3d001800     	str	b0, [x0, #6]
  201fe0: 36180726     	tbz	w6, #3, 0x2020c4 <custom_memset+0x164>
  201fe4: 3d001c00     	str	b0, [x0, #7]
  201fe8: f100207f     	cmp	x3, #8
  201fec: 54000709     	b.ls	0x2020cc <custom_memset+0x16c>
  201ff0: 3d002000     	str	b0, [x0, #8]
  201ff4: f100247f     	cmp	x3, #9
  201ff8: 54000280     	b.eq	0x202048 <custom_memset+0xe8>
  201ffc: 3d002400     	str	b0, [x0, #9]
  202000: f100287f     	cmp	x3, #10
  202004: 54000220     	b.eq	0x202048 <custom_memset+0xe8>
  202008: 3d002800     	str	b0, [x0, #10]
  20200c: f1002c7f     	cmp	x3, #11
  202010: 540001c0     	b.eq	0x202048 <custom_memset+0xe8>
  202014: 3d002c00     	str	b0, [x0, #11]
  202018: f100307f     	cmp	x3, #12
  20201c: 54000160     	b.eq	0x202048 <custom_memset+0xe8>
  202020: 3d003000     	str	b0, [x0, #12]
  202024: f100347f     	cmp	x3, #13
  202028: 54000100     	b.eq	0x202048 <custom_memset+0xe8>
  20202c: d1000401     	sub	x1, x0, #1
  202030: 3d003400     	str	b0, [x0, #13]
  202034: f2400c3f     	tst	x1, #0xf
  202038: 540004e1     	b.ne	0x2020d4 <custom_memset+0x174>
  20203c: d28001e5     	mov	x5, #15
  202040: 3d003800     	str	b0, [x0, #14]
  202044: 14000002     	b	0x20204c <custom_memset+0xec>
  202048: aa0303e5     	mov	x5, x3
  20204c: cb030044     	sub	x4, x2, x3
  202050: 8b030001     	add	x1, x0, x3
  202054: 4e010401     	dup	v1.16b, v0.b[0]
  202058: 927cec83     	and	x3, x4, #0xfffffffffffffff0
  20205c: 8b010063     	add	x3, x3, x1
  202060: 3c810421     	str	q1, [x1], #16
  202064: eb03003f     	cmp	x1, x3
  202068: 54ffffc1     	b.ne	0x202060 <custom_memset+0x100>
  20206c: 927cec81     	and	x1, x4, #0xfffffffffffffff0
  202070: f2400c9f     	tst	x4, #0xf
  202074: 8b050021     	add	x1, x1, x5
  202078: 540000c0     	b.eq	0x202090 <custom_memset+0x130>
  20207c: d503201f     	nop
  202080: 3c216800     	str	b0, [x0, x1]
  202084: 91000421     	add	x1, x1, #1
  202088: eb01005f     	cmp	x2, x1
  20208c: 54ffffa8     	b.hi	0x202080 <custom_memset+0x120>
  202090: d65f03c0     	ret
  202094: d2800085     	mov	x5, #4
  202098: 17ffffed     	b	0x20204c <custom_memset+0xec>
  20209c: d2800001     	mov	x1, #0
  2020a0: 17fffff8     	b	0x202080 <custom_memset+0x120>
  2020a4: d2800025     	mov	x5, #1
  2020a8: 17ffffe9     	b	0x20204c <custom_memset+0xec>
  2020ac: d2800045     	mov	x5, #2
  2020b0: 17ffffe7     	b	0x20204c <custom_memset+0xec>
  2020b4: d2800065     	mov	x5, #3
  2020b8: 17ffffe5     	b	0x20204c <custom_memset+0xec>
  2020bc: d2800005     	mov	x5, #0
  2020c0: 17ffffe3     	b	0x20204c <custom_memset+0xec>
  2020c4: d28000e5     	mov	x5, #7
  2020c8: 17ffffe1     	b	0x20204c <custom_memset+0xec>
  2020cc: d2800105     	mov	x5, #8
  2020d0: 17ffffdf     	b	0x20204c <custom_memset+0xec>
  2020d4: d28001c5     	mov	x5, #14
  2020d8: 17ffffdd     	b	0x20204c <custom_memset+0xec>
  2020dc: d503201f     	nop

00000000002020e0 <putvar>:
  2020e0: a9bc7bfd     	stp	x29, x30, [sp, #-64]!
  2020e4: 910003fd     	mov	x29, sp
  2020e8: f9000bf3     	str	x19, [sp, #16]
  2020ec: aa0003f3     	mov	x19, x0
  2020f0: aa0103e0     	mov	x0, x1
  2020f4: 940000df     	bl	0x202470 <microkit_dbg_puts>
  2020f8: 90000000     	adrp	x0, 0x202000 <putvar+0x18>
  2020fc: 91344000     	add	x0, x0, #3344
  202100: 940000dc     	bl	0x202470 <microkit_dbg_puts>
  202104: 3900e3ff     	strb	wzr, [sp, #56]
  202108: b50001d3     	cbnz	x19, 0x202140 <putvar+0x60>
  20210c: 52800600     	mov	w0, #48
  202110: d28001f3     	mov	x19, #15
  202114: 3900dfe0     	strb	w0, [sp, #55]
  202118: 90000000     	adrp	x0, 0x202000 <putvar+0x38>
  20211c: 91220000     	add	x0, x0, #2176
  202120: 940000d4     	bl	0x202470 <microkit_dbg_puts>
  202124: 9100a3e0     	add	x0, sp, #40
  202128: 8b130000     	add	x0, x0, x19
  20212c: 940000d1     	bl	0x202470 <microkit_dbg_puts>
  202130: f9400bf3     	ldr	x19, [sp, #16]
  202134: 52800140     	mov	w0, #10
  202138: a8c47bfd     	ldp	x29, x30, [sp], #64
  20213c: 140000c1     	b	0x202440 <microkit_dbg_putc>
  202140: 12000e60     	and	w0, w19, #0xf
  202144: d344fe61     	lsr	x1, x19, #4
  202148: 7100281f     	cmp	w0, #10
  20214c: 11015c02     	add	w2, w0, #87
  202150: 1100c000     	add	w0, w0, #48
  202154: 1a823000     	csel	w0, w0, w2, lo
  202158: 3900dfe0     	strb	w0, [sp, #55]
  20215c: b4000f21     	cbz	x1, 0x202340 <putvar+0x260>
  202160: 12000c20     	and	w0, w1, #0xf
  202164: d348fe61     	lsr	x1, x19, #8
  202168: 7100281f     	cmp	w0, #10
  20216c: 11015c02     	add	w2, w0, #87
  202170: 1100c000     	add	w0, w0, #48
  202174: 1a823000     	csel	w0, w0, w2, lo
  202178: 3900dbe0     	strb	w0, [sp, #54]
  20217c: b4000ee1     	cbz	x1, 0x202358 <putvar+0x278>
  202180: 12000c20     	and	w0, w1, #0xf
  202184: d34cfe61     	lsr	x1, x19, #12
  202188: 7100281f     	cmp	w0, #10
  20218c: 11015c02     	add	w2, w0, #87
  202190: 1100c000     	add	w0, w0, #48
  202194: 1a823000     	csel	w0, w0, w2, lo
  202198: 3900d7e0     	strb	w0, [sp, #53]
  20219c: b4000e41     	cbz	x1, 0x202364 <putvar+0x284>
  2021a0: 12000c20     	and	w0, w1, #0xf
  2021a4: d350fe61     	lsr	x1, x19, #16
  2021a8: 7100281f     	cmp	w0, #10
  2021ac: 11015c02     	add	w2, w0, #87
  2021b0: 1100c000     	add	w0, w0, #48
  2021b4: 1a823000     	csel	w0, w0, w2, lo
  2021b8: 3900d3e0     	strb	w0, [sp, #52]
  2021bc: b4000da1     	cbz	x1, 0x202370 <putvar+0x290>
  2021c0: 12000c20     	and	w0, w1, #0xf
  2021c4: d354fe61     	lsr	x1, x19, #20
  2021c8: 7100281f     	cmp	w0, #10
  2021cc: 11015c02     	add	w2, w0, #87
  2021d0: 1100c000     	add	w0, w0, #48
  2021d4: 1a823000     	csel	w0, w0, w2, lo
  2021d8: 3900cfe0     	strb	w0, [sp, #51]
  2021dc: b4000d01     	cbz	x1, 0x20237c <putvar+0x29c>
  2021e0: 12000c20     	and	w0, w1, #0xf
  2021e4: d358fe61     	lsr	x1, x19, #24
  2021e8: 7100281f     	cmp	w0, #10
  2021ec: 11015c02     	add	w2, w0, #87
  2021f0: 1100c000     	add	w0, w0, #48
  2021f4: 1a823000     	csel	w0, w0, w2, lo
  2021f8: 3900cbe0     	strb	w0, [sp, #50]
  2021fc: b4000c61     	cbz	x1, 0x202388 <putvar+0x2a8>
  202200: 12000c20     	and	w0, w1, #0xf
  202204: d35cfe61     	lsr	x1, x19, #28
  202208: 7100281f     	cmp	w0, #10
  20220c: 11015c02     	add	w2, w0, #87
  202210: 1100c000     	add	w0, w0, #48
  202214: 1a823000     	csel	w0, w0, w2, lo
  202218: 3900c7e0     	strb	w0, [sp, #49]
  20221c: b4000bc1     	cbz	x1, 0x202394 <putvar+0x2b4>
  202220: 12000c20     	and	w0, w1, #0xf
  202224: d360fe61     	lsr	x1, x19, #32
  202228: 7100281f     	cmp	w0, #10
  20222c: 11015c02     	add	w2, w0, #87
  202230: 1100c000     	add	w0, w0, #48
  202234: 1a823000     	csel	w0, w0, w2, lo
  202238: 3900c3e0     	strb	w0, [sp, #48]
  20223c: b4000881     	cbz	x1, 0x20234c <putvar+0x26c>
  202240: 12000c20     	and	w0, w1, #0xf
  202244: d364fe61     	lsr	x1, x19, #36
  202248: 7100281f     	cmp	w0, #10
  20224c: 11015c02     	add	w2, w0, #87
  202250: 1100c000     	add	w0, w0, #48
  202254: 1a823000     	csel	w0, w0, w2, lo
  202258: 3900bfe0     	strb	w0, [sp, #47]
  20225c: b4000a21     	cbz	x1, 0x2023a0 <putvar+0x2c0>
  202260: 12000c20     	and	w0, w1, #0xf
  202264: d368fe61     	lsr	x1, x19, #40
  202268: 7100281f     	cmp	w0, #10
  20226c: 11015c02     	add	w2, w0, #87
  202270: 1100c000     	add	w0, w0, #48
  202274: 1a823000     	csel	w0, w0, w2, lo
  202278: 3900bbe0     	strb	w0, [sp, #46]
  20227c: b4000981     	cbz	x1, 0x2023ac <putvar+0x2cc>
  202280: 12000c20     	and	w0, w1, #0xf
  202284: d36cfe61     	lsr	x1, x19, #44
  202288: 7100281f     	cmp	w0, #10
  20228c: 11015c02     	add	w2, w0, #87
  202290: 1100c000     	add	w0, w0, #48
  202294: 1a823000     	csel	w0, w0, w2, lo
  202298: 3900b7e0     	strb	w0, [sp, #45]
  20229c: b40008e1     	cbz	x1, 0x2023b8 <putvar+0x2d8>
  2022a0: 12000c20     	and	w0, w1, #0xf
  2022a4: d370fe61     	lsr	x1, x19, #48
  2022a8: 7100281f     	cmp	w0, #10
  2022ac: 11015c02     	add	w2, w0, #87
  2022b0: 1100c000     	add	w0, w0, #48
  2022b4: 1a823000     	csel	w0, w0, w2, lo
  2022b8: 3900b3e0     	strb	w0, [sp, #44]
  2022bc: b4000841     	cbz	x1, 0x2023c4 <putvar+0x2e4>
  2022c0: 12000c20     	and	w0, w1, #0xf
  2022c4: d374fe61     	lsr	x1, x19, #52
  2022c8: 7100281f     	cmp	w0, #10
  2022cc: 11015c02     	add	w2, w0, #87
  2022d0: 1100c000     	add	w0, w0, #48
  2022d4: 1a823000     	csel	w0, w0, w2, lo
  2022d8: 3900afe0     	strb	w0, [sp, #43]
  2022dc: b40007a1     	cbz	x1, 0x2023d0 <putvar+0x2f0>
  2022e0: 12000c20     	and	w0, w1, #0xf
  2022e4: d378fe61     	lsr	x1, x19, #56
  2022e8: 7100281f     	cmp	w0, #10
  2022ec: 11015c02     	add	w2, w0, #87
  2022f0: 1100c000     	add	w0, w0, #48
  2022f4: 1a823000     	csel	w0, w0, w2, lo
  2022f8: 3900abe0     	strb	w0, [sp, #42]
  2022fc: b4000701     	cbz	x1, 0x2023dc <putvar+0x2fc>
  202300: 12000c20     	and	w0, w1, #0xf
  202304: d37cfe73     	lsr	x19, x19, #60
  202308: 7100281f     	cmp	w0, #10
  20230c: 11015c01     	add	w1, w0, #87
  202310: 1100c000     	add	w0, w0, #48
  202314: 1a813000     	csel	w0, w0, w1, lo
  202318: 3900a7e0     	strb	w0, [sp, #41]
  20231c: b4000673     	cbz	x19, 0x2023e8 <putvar+0x308>
  202320: 7100267f     	cmp	w19, #9
  202324: 1100c260     	add	w0, w19, #48
  202328: 52800001     	mov	w1, #0
  20232c: 11015e73     	add	w19, w19, #87
  202330: 1a808260     	csel	w0, w19, w0, hi
  202334: 93407c33     	sxtw	x19, w1
  202338: 3900a3e0     	strb	w0, [sp, #40]
  20233c: 17ffff77     	b	0x202118 <putvar+0x38>
  202340: 528001e1     	mov	w1, #15
  202344: 93407c33     	sxtw	x19, w1
  202348: 17ffff74     	b	0x202118 <putvar+0x38>
  20234c: 52800101     	mov	w1, #8
  202350: 93407c33     	sxtw	x19, w1
  202354: 17ffff71     	b	0x202118 <putvar+0x38>
  202358: 528001c1     	mov	w1, #14
  20235c: 93407c33     	sxtw	x19, w1
  202360: 17ffff6e     	b	0x202118 <putvar+0x38>
  202364: 528001a1     	mov	w1, #13
  202368: 93407c33     	sxtw	x19, w1
  20236c: 17ffff6b     	b	0x202118 <putvar+0x38>
  202370: 52800181     	mov	w1, #12
  202374: 93407c33     	sxtw	x19, w1
  202378: 17ffff68     	b	0x202118 <putvar+0x38>
  20237c: 52800161     	mov	w1, #11
  202380: 93407c33     	sxtw	x19, w1
  202384: 17ffff65     	b	0x202118 <putvar+0x38>
  202388: 52800141     	mov	w1, #10
  20238c: 93407c33     	sxtw	x19, w1
  202390: 17ffff62     	b	0x202118 <putvar+0x38>
  202394: 52800121     	mov	w1, #9
  202398: 93407c33     	sxtw	x19, w1
  20239c: 17ffff5f     	b	0x202118 <putvar+0x38>
  2023a0: 528000e1     	mov	w1, #7
  2023a4: 93407c33     	sxtw	x19, w1
  2023a8: 17ffff5c     	b	0x202118 <putvar+0x38>
  2023ac: 528000c1     	mov	w1, #6
  2023b0: 93407c33     	sxtw	x19, w1
  2023b4: 17ffff59     	b	0x202118 <putvar+0x38>
  2023b8: 528000a1     	mov	w1, #5
  2023bc: 93407c33     	sxtw	x19, w1
  2023c0: 17ffff56     	b	0x202118 <putvar+0x38>
  2023c4: 52800081     	mov	w1, #4
  2023c8: 93407c33     	sxtw	x19, w1
  2023cc: 17ffff53     	b	0x202118 <putvar+0x38>
  2023d0: 52800061     	mov	w1, #3
  2023d4: 93407c33     	sxtw	x19, w1
  2023d8: 17ffff50     	b	0x202118 <putvar+0x38>
  2023dc: 52800041     	mov	w1, #2
  2023e0: 93407c33     	sxtw	x19, w1
  2023e4: 17ffff4d     	b	0x202118 <putvar+0x38>
  2023e8: 52800021     	mov	w1, #1
  2023ec: 93407c33     	sxtw	x19, w1
  2023f0: 17ffff4a     	b	0x202118 <putvar+0x38>
  2023f4: d503201f     	nop
  2023f8: d503201f     	nop
  2023fc: d503201f     	nop

0000000000202400 <custom_strcmp>:
  202400: 39400002     	ldrb	w2, [x0]
  202404: 350000a2     	cbnz	w2, 0x202418 <custom_strcmp+0x18>
  202408: 1400000a     	b	0x202430 <custom_strcmp+0x30>
  20240c: 540000e1     	b.ne	0x202428 <custom_strcmp+0x28>
  202410: 38401c02     	ldrb	w2, [x0, #1]!
  202414: 340000e2     	cbz	w2, 0x202430 <custom_strcmp+0x30>
  202418: 39400023     	ldrb	w3, [x1]
  20241c: 91000421     	add	x1, x1, #1
  202420: 6b02007f     	cmp	w3, w2
  202424: 35ffff43     	cbnz	w3, 0x20240c <custom_strcmp+0xc>
  202428: 52800020     	mov	w0, #1
  20242c: d65f03c0     	ret
  202430: 39400020     	ldrb	w0, [x1]
  202434: 7100001f     	cmp	w0, #0
  202438: 1a9f07e0     	cset	w0, ne
  20243c: d65f03c0     	ret

0000000000202440 <microkit_dbg_putc>:
  202440: d2800001     	mov	x1, #0
  202444: 92401c00     	and	x0, x0, #0xff
  202448: d2800002     	mov	x2, #0
  20244c: d2800003     	mov	x3, #0
  202450: d2800004     	mov	x4, #0
  202454: d2800005     	mov	x5, #0
  202458: d2800006     	mov	x6, #0
  20245c: 92800167     	mov	x7, #-12
  202460: d4000001     	svc	#0
  202464: d65f03c0     	ret
  202468: d503201f     	nop
  20246c: d503201f     	nop

0000000000202470 <microkit_dbg_puts>:
  202470: aa0003e8     	mov	x8, x0
  202474: 39400000     	ldrb	w0, [x0]
  202478: 34000180     	cbz	w0, 0x2024a8 <microkit_dbg_puts+0x38>
  20247c: d503201f     	nop
  202480: d2800001     	mov	x1, #0
  202484: d2800002     	mov	x2, #0
  202488: d2800003     	mov	x3, #0
  20248c: d2800004     	mov	x4, #0
  202490: d2800005     	mov	x5, #0
  202494: d2800006     	mov	x6, #0
  202498: 92800167     	mov	x7, #-12
  20249c: d4000001     	svc	#0
  2024a0: 38401d00     	ldrb	w0, [x8, #1]!
  2024a4: 35fffee0     	cbnz	w0, 0x202480 <microkit_dbg_puts+0x10>
  2024a8: d65f03c0     	ret
  2024ac: d503201f     	nop

00000000002024b0 <__assert_fail>:
  2024b0: 9000000b     	adrp	x11, 0x202000 <__assert_fail>
  2024b4: 9136616b     	add	x11, x11, #3480
  2024b8: aa0103e9     	mov	x9, x1
  2024bc: aa0303e8     	mov	x8, x3
  2024c0: aa0003ea     	mov	x10, x0
  2024c4: d2800c20     	mov	x0, #97
  2024c8: d2800001     	mov	x1, #0
  2024cc: d2800002     	mov	x2, #0
  2024d0: d2800003     	mov	x3, #0
  2024d4: d2800004     	mov	x4, #0
  2024d8: d2800005     	mov	x5, #0
  2024dc: d2800006     	mov	x6, #0
  2024e0: 92800167     	mov	x7, #-12
  2024e4: d4000001     	svc	#0
  2024e8: 38401d60     	ldrb	w0, [x11, #1]!
  2024ec: 35fffee0     	cbnz	w0, 0x2024c8 <__assert_fail+0x18>
  2024f0: 39400140     	ldrb	w0, [x10]
  2024f4: 34000160     	cbz	w0, 0x202520 <__assert_fail+0x70>
  2024f8: d2800001     	mov	x1, #0
  2024fc: d2800002     	mov	x2, #0
  202500: d2800003     	mov	x3, #0
  202504: d2800004     	mov	x4, #0
  202508: d2800005     	mov	x5, #0
  20250c: d2800006     	mov	x6, #0
  202510: 92800167     	mov	x7, #-12
  202514: d4000001     	svc	#0
  202518: 38401d40     	ldrb	w0, [x10, #1]!
  20251c: 35fffee0     	cbnz	w0, 0x2024f8 <__assert_fail+0x48>
  202520: d2800400     	mov	x0, #32
  202524: d2800001     	mov	x1, #0
  202528: d2800002     	mov	x2, #0
  20252c: d2800003     	mov	x3, #0
  202530: d2800004     	mov	x4, #0
  202534: d2800005     	mov	x5, #0
  202538: d2800006     	mov	x6, #0
  20253c: 92800167     	mov	x7, #-12
  202540: d4000001     	svc	#0
  202544: 39400120     	ldrb	w0, [x9]
  202548: 34000180     	cbz	w0, 0x202578 <__assert_fail+0xc8>
  20254c: d503201f     	nop
  202550: d2800001     	mov	x1, #0
  202554: d2800002     	mov	x2, #0
  202558: d2800003     	mov	x3, #0
  20255c: d2800004     	mov	x4, #0
  202560: d2800005     	mov	x5, #0
  202564: d2800006     	mov	x6, #0
  202568: 92800167     	mov	x7, #-12
  20256c: d4000001     	svc	#0
  202570: 38401d20     	ldrb	w0, [x9, #1]!
  202574: 35fffee0     	cbnz	w0, 0x202550 <__assert_fail+0xa0>
  202578: d2800400     	mov	x0, #32
  20257c: d2800001     	mov	x1, #0
  202580: d2800002     	mov	x2, #0
  202584: d2800003     	mov	x3, #0
  202588: d2800004     	mov	x4, #0
  20258c: d2800005     	mov	x5, #0
  202590: d2800006     	mov	x6, #0
  202594: 92800167     	mov	x7, #-12
  202598: d4000001     	svc	#0
  20259c: 39400100     	ldrb	w0, [x8]
  2025a0: 34000180     	cbz	w0, 0x2025d0 <__assert_fail+0x120>
  2025a4: d503201f     	nop
  2025a8: d2800001     	mov	x1, #0
  2025ac: d2800002     	mov	x2, #0
  2025b0: d2800003     	mov	x3, #0
  2025b4: d2800004     	mov	x4, #0
  2025b8: d2800005     	mov	x5, #0
  2025bc: d2800006     	mov	x6, #0
  2025c0: 92800167     	mov	x7, #-12
  2025c4: d4000001     	svc	#0
  2025c8: 38401d00     	ldrb	w0, [x8, #1]!
  2025cc: 35fffee0     	cbnz	w0, 0x2025a8 <__assert_fail+0xf8>
  2025d0: d2800140     	mov	x0, #10
  2025d4: d2800001     	mov	x1, #0
  2025d8: d2800002     	mov	x2, #0
  2025dc: d2800003     	mov	x3, #0
  2025e0: d2800004     	mov	x4, #0
  2025e4: d2800005     	mov	x5, #0
  2025e8: d2800006     	mov	x6, #0
  2025ec: 92800167     	mov	x7, #-12
  2025f0: d4000001     	svc	#0
  2025f4: d65f03c0     	ret
		...

0000000000202600 <protected>:
  202600: a9bf7bfd     	stp	x29, x30, [sp, #-16]!
  202604: b0000000     	adrp	x0, 0x203000 <protected+0x8>
  202608: 91004000     	add	x0, x0, #16
  20260c: 910003fd     	mov	x29, sp
  202610: 97ffff98     	bl	0x202470 <microkit_dbg_puts>
  202614: 90000000     	adrp	x0, 0x202000 <protected+0x14>
  202618: 9136a000     	add	x0, x0, #3496
  20261c: 97ffff95     	bl	0x202470 <microkit_dbg_puts>
  202620: d2800000     	mov	x0, #0
  202624: b900001f     	str	wzr, [x0]
  202628: d4207d00     	brk	#0x3e8
  20262c: d503201f     	nop

0000000000202630 <fault>:
  202630: a9bf7bfd     	stp	x29, x30, [sp, #-16]!
  202634: b0000000     	adrp	x0, 0x203000 <fault+0x8>
  202638: 91004000     	add	x0, x0, #16
  20263c: 910003fd     	mov	x29, sp
  202640: 97ffff8c     	bl	0x202470 <microkit_dbg_puts>
  202644: 90000000     	adrp	x0, 0x202000 <fault+0x14>
  202648: 91376000     	add	x0, x0, #3544
  20264c: 97ffff89     	bl	0x202470 <microkit_dbg_puts>
  202650: d2800000     	mov	x0, #0
  202654: b900001f     	str	wzr, [x0]
  202658: d4207d00     	brk	#0x3e8
  20265c: 00000000     	udf	#0

0000000000202660 <main>:
  202660: a9bc7bfd     	stp	x29, x30, [sp, #-64]!
  202664: 90000000     	adrp	x0, 0x202000 <main+0x4>
  202668: 91380000     	add	x0, x0, #3584
  20266c: 910003fd     	mov	x29, sp
  202670: a90153f3     	stp	x19, x20, [sp, #16]
  202674: b0000014     	adrp	x20, 0x203000 <main+0x18>
  202678: 91000294     	add	x20, x20, #0
  20267c: a9025bf5     	stp	x21, x22, [sp, #32]
  202680: 97ffff7c     	bl	0x202470 <microkit_dbg_puts>
  202684: b0000000     	adrp	x0, 0x203000 <main+0x28>
  202688: 91000000     	add	x0, x0, #0
  20268c: eb140015     	subs	x21, x0, x20
  202690: 54000120     	b.eq	0x2026b4 <main+0x54>
  202694: 9343feb5     	asr	x21, x21, #3
  202698: d2800013     	mov	x19, #0
  20269c: d503201f     	nop
  2026a0: f8737a80     	ldr	x0, [x20, x19, lsl #3]
  2026a4: 91000673     	add	x19, x19, #1
  2026a8: d63f0000     	blr	x0
  2026ac: eb1302bf     	cmp	x21, x19
  2026b0: 54ffff88     	b.hi	0x2026a0 <main+0x40>
  2026b4: b0000016     	adrp	x22, 0x203000 <main+0x58>
  2026b8: 910042d6     	add	x22, x22, #16
  2026bc: 97fff655     	bl	0x200010 <init>
  2026c0: 394102c0     	ldrb	w0, [x22, #64]
  2026c4: 340000a0     	cbz	w0, 0x2026d8 <main+0x78>
  2026c8: 52800021     	mov	w1, #1
  2026cc: d28000a0     	mov	x0, #5
  2026d0: 390106c1     	strb	w1, [x22, #65]
  2026d4: a90482df     	stp	xzr, x0, [x22, #72]
  2026d8: b0000015     	adrp	x21, 0x203000 <main+0x7c>
  2026dc: 910002b5     	add	x21, x21, #0
  2026e0: 52800000     	mov	w0, #0
  2026e4: d503201f     	nop
  2026e8: 35000220     	cbnz	w0, 0x20272c <main+0xcc>
  2026ec: 39c106c0     	ldrsb	w0, [x22, #65]
  2026f0: 350004e0     	cbnz	w0, 0x20278c <main+0x12c>
  2026f4: d2800020     	mov	x0, #1
  2026f8: d2800086     	mov	x6, #4
  2026fc: 928000c7     	mov	x7, #-7
  202700: d4000001     	svc	#0
  202704: f94002a6     	ldr	x6, [x21]
  202708: aa0003f3     	mov	x19, x0
  20270c: a9008cc2     	stp	x2, x3, [x6, #8]
  202710: a90194c4     	stp	x4, x5, [x6, #24]
  202714: b7f00313     	tbnz	x19, #62, 0x202774 <main+0x114>
  202718: 52800014     	mov	w20, #0
  20271c: b6f801b3     	tbz	x19, #63, 0x202750 <main+0xf0>
  202720: 12001660     	and	w0, w19, #0x3f
  202724: 97ffffb7     	bl	0x202600 <protected>
  202728: f9001fe0     	str	x0, [sp, #56]
  20272c: f94002a5     	ldr	x5, [x21]
  202730: d2800020     	mov	x0, #1
  202734: f9401fe1     	ldr	x1, [sp, #56]
  202738: d2800086     	mov	x6, #4
  20273c: a9408ca2     	ldp	x2, x3, [x5, #8]
  202740: 92800027     	mov	x7, #-2
  202744: a94194a4     	ldp	x4, x5, [x5, #24]
  202748: d4000001     	svc	#0
  20274c: 17ffffee     	b	0x202704 <main+0xa4>
  202750: 370000d3     	tbnz	w19, #0, 0x202768 <main+0x108>
  202754: d503201f     	nop
  202758: d341fe73     	lsr	x19, x19, #1
  20275c: 11000694     	add	w20, w20, #1
  202760: b4fffc73     	cbz	x19, 0x2026ec <main+0x8c>
  202764: 3607ffb3     	tbz	w19, #0, 0x202758 <main+0xf8>
  202768: 2a1403e0     	mov	w0, w20
  20276c: 97fff645     	bl	0x200080 <notified>
  202770: 17fffffa     	b	0x202758 <main+0xf8>
  202774: 12001e60     	and	w0, w19, #0xff
  202778: 9100e3e2     	add	x2, sp, #56
  20277c: 97ffffad     	bl	0x202630 <fault>
  202780: 72001c1f     	tst	w0, #0xff
  202784: 1a9f07e0     	cset	w0, ne
  202788: 17ffffd8     	b	0x2026e8 <main+0x88>
  20278c: f94002a5     	ldr	x5, [x21]
  202790: d2800020     	mov	x0, #1
  202794: a944a2c1     	ldp	x1, x8, [x22, #72]
  202798: d2800086     	mov	x6, #4
  20279c: a9408ca2     	ldp	x2, x3, [x5, #8]
  2027a0: 92800047     	mov	x7, #-3
  2027a4: a94194a4     	ldp	x4, x5, [x5, #24]
  2027a8: d4000001     	svc	#0
  2027ac: f94002a6     	ldr	x6, [x21]
  2027b0: aa0003f3     	mov	x19, x0
  2027b4: 390106df     	strb	wzr, [x22, #65]
  2027b8: a9008cc2     	stp	x2, x3, [x6, #8]
  2027bc: a90194c4     	stp	x4, x5, [x6, #24]
  2027c0: 17ffffd5     	b	0x202714 <main+0xb4>
  2027c4: 00000000     	udf	#0

00000000002027c8 <$d>:
  2027c8: 18 2d 20 00  	.word	0x00202d18
  2027cc: 00 00 00 00  	.word	0x00000000
  2027d0: 30 2d 20 00  	.word	0x00202d30
  2027d4: 00 00 00 00  	.word	0x00000000
  2027d8: 48 2d 20 00  	.word	0x00202d48
  2027dc: 00 00 00 00  	.word	0x00000000
  2027e0: 60 2d 20 00  	.word	0x00202d60
  2027e4: 00 00 00 00  	.word	0x00000000
  2027e8: 80 2d 20 00  	.word	0x00202d80
  2027ec: 00 00 00 00  	.word	0x00000000
