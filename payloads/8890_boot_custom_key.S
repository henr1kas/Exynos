.text
.global _start

_start:
	b _stage1
	b _stage2

_stage1:
	ldr w0, _dst_ptr
	ldr w1, _bl1_ptr
	mov w2, 0x200
	mov w4, w0
_copy:
	ldr x3, [x1], #8
	str x3, [x0], #8
	subs x2, x2, #8
	bne _copy
	add x4, x4, #0x4
	br x4

.align 4
_bl1_ptr: .dword 0x02021800
_dst_ptr: .dword 0x02069000

_stage2:
    mov     x0, #0x330c
    movk    x0, #0x105c, lsl #16
    mov     w1, #0x5300
    str     w1, [x0]

    mov     x0, #0x006c
    movk    x0, #0x0202, lsl #16
    adr     x1, efuse
    str     w1, [x0]

    ldp x29, x30, [sp, #0x10]
    add sp, sp, #0x20
    ldp x19, x20, [sp, #0x10]
    ldp x21, x22, [sp, #0x20]
    ldp x29, x30, [sp, #0x30]
    add sp, sp, #0x40
    ldp x19, x29, [sp]
    ldr x30, [sp, #0x10]
    add sp, sp, #0x20
    ldp x19, x20, [sp]
    ldp x29, x30, [sp, #0x10]
    add sp, sp, #0x20

    ic iallu

    br x19

.align 4
efuse:
    .incbin "efuse_0.bin"
