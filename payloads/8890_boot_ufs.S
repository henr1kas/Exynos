.text
.global _start

_start:
    b       loader
    .zero   0x1FFC

loader:
    mov     x2, #0x6C
    movk    x2, #0x202, lsl #16
    adr     x1, efuse
    str     w1, [x2]

    movz    x0, #0x1CA0
    movk    x0, #0x1, lsl #16
    mov     x16, #0x2258
    blr     x16

    mov     w0, #1
    mov     w1, #1
    movz    x16, #0x2848
    movk    x16, #0x1, lsl #16
    blr     x16

    mov     x0, #0x008c
    movk    x0, #0x0202, lsl #16
    mov     x16, #0x18e0
    blr     x16

    mov     x0, #0x300000
    mov     x16, #0x00e8
    movk    x16, #0x0202, lsl #16
    ldr     w16, [x16]
    blr     x16

    ic iallu

    movz    x4, #0x9310
    movk    x4, #0x1, lsl #16
    br      x4

efuse:
    .incbin "efuse_0.bin"
