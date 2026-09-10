.text
.global _start

// must be placed inside +0x2000 of bl1, then from exploit load 0x02024000 when sending BL1 as a payload
// this will load BL1 normally but with 0x0202006c replaced to our key ptr

_start:
    mov     x0, #0x00e0
    movk    x0, #0x0202, lsl #16
    mov     x3, #0x0
    ldr     w3, [x0]
    mov     x0, #0x1400
    movk    x0, #0x0202, lsl #16
    mov     x1, #300
    mov     x2, #0x0
    blr     x3

    mov     x16, #0x48bc
    blr     x16

    mov     x16, #0xa628
    blr     x16
    cbz     w0, fail_header

    mov     x16, #0x2274
    blr     x16
    cbz     w0, fail_checksum

    movz    x1, #0x4130
    movk    x1, #0x0202, lsl #16
    mov     x0, #0x006c
    movk    x0, #0x0202, lsl #16
    str     w1, [x0]

    mov     w0, #1
    mov     x16, #0xb5f4
    blr     x16
    cmp     w0, #1
    b.ne    fail_verify

    mov     x16, #0x21a0
    blr     x16
    cmp     w0, #1
    b.ne    fail_check

    movz    x16, #0x2a94
    movk    x16, #0x1, lsl #16
    blr     x16

    mov     x0, #0x008c
    movk    x0, #0x0202, lsl #16
    mov     x16, #0xa828
    blr     x16

    mov     x0, #0
    movz    x1, #0
    movk    x1, #0x80, lsl #16
    movz    x16, #0x62e4
    movk    x16, #0x1, lsl #16
    blr     x16

    mov     x4, #0x1120
    br      x4

fail_header:
    MOV     X1, #0xD0
    MOVK    X1, #0x202,LSL#16
    LDR     W3, [X1]
    MOV     X0, #0xA5FF
    MOVK    X0, #0x1, LSL #16
    MOV     X1, #15
    BLR     X3
	RET

fail_checksum:
    MOV     X1, #0xD0
    MOVK    X1, #0x202,LSL#16
    LDR     W3, [X1]
    MOV     X0, #0xA5ED
    MOVK    X0, #0x1, LSL #16
    MOV     X1, #17
    BLR     X3
	RET

fail_verify:
    MOV     X1, #0xD0
    MOVK    X1, #0x202,LSL#16
    LDR     W3, [X1]
    ADR     X0, aBl1VerifyFail
    MOV     X1, #15
    BLR     X3
	RET

fail_check:
    MOV     X1, #0xD0
    MOVK    X1, #0x202,LSL#16
    LDR     W3, [X1]
    ADR     X0, aBl1CheckFail
    MOV     X1, #14
    BLR     X3
	RET

.align 4
efuse:
    .incbin "efuse_4.bin"
aBl1VerifyFail:
    .string "BL1 Verify Fail"
aBl1CheckFail:
    .string "BL1 Check Fail"