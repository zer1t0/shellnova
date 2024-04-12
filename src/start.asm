
extern main

SECTION .text$start
global _start_shc

_start_shc:
  push r12
  mov r12, rsp
  and rsp, 0FFFFFFFFFFFFFFF0h
  sub rsp, 0x20
  call main
  mov rsp, r12
  pop r12
  ret

SECTION .text$end

_end_shc:
  db 'E', 'N', 'D', 'S', 'H', 'C'
