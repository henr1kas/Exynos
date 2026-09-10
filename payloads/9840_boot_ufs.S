.text
.global _start

_start:
    b       loader
    .zero   0x2FFC

loader:
    mov     w1, #2
    movz    x20, #0x62E4
    movk    x20, #1, lsl #16
    mov     w0, #0
    blr     x20

    mov     x0, #0xA7F4
    blr     x0

    mov     x1, #0x30F4
    blr     x1

    mov     w1, #8
    mov     w0, #0
    blr     x20

    mov     x0, #0x48BC
    blr     x0
    mov     w19, w0

    mov     x2, #0x6C
    movk    x2, #0x202, lsl #16
    adr     x1, efuse
    str     w1, [x2]

    ldur    w1, [x2, #-8]
    and     w1, w1, #0xFFFFFF
    and     w1, w1, #0xFFFFFF0F
    movz    w0, #0x0010
    movk    w0, #0xCB00, lsl #16
    orr     w1, w1, w0
    stur    w1, [x2, #-8]

    mov     w0, #1
    mov     x1, #0x54B8
    blr     x1
    cmp     w0, #1
    b.ne    fail

    mov     w0, w19
    mov     x1, #0xB5F4
    blr     x1
    cmp     w0, #1
    b.ne    fail

    mov     x0, #0x21A0
    blr     x0
    cmp     w0, #1
    b.ne    fail

    movz    x0, #0x2A94
    movk    x0, #0x0001, lsl #16
    blr     x0

    mov     w0, #0x8C
    movk    w0, #0x202, lsl #16
    mov     x1, #0xA828
    blr     x1

    mov     w1, #0x800000
    mov     w0, #0
    blr     x20

    mov     x0, #0x1120
    br      x0

fail:
    b       fail
efuse:
    .incbin "efuse_4.bin"
