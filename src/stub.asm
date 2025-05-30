section .text
    global _start

_start:
    call get_rip         
get_rip:
    pop rsi
    add rsi, 0x0          
    mov rcx, 0x0            
    mov al, 0x00             

xor_loop:
    test rcx, rcx
    jz xor_done
    xor byte [rsi], al
    inc rsi
    dec rcx
    jmp xor_loop

xor_done:
    call 0x00

