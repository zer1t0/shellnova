
extern premain

SECTION .text$start
global _start_shc
global get_start_addr
global get_end_addr

_start_shc:
  push r12
  mov r12, rsp
  and rsp, 0FFFFFFFFFFFFFFF0h
  sub rsp, 0x20
  call premain
  mov rsp, r12
  pop r12
  ret

get_start_addr:
  call _get_ret_addr
  sub rax, 0x1d
  ret

_get_ret_addr:
  pop rax
  push rax
  ret

SECTION .text$end

;;  WARNING: This function cannot be invoked once the memory permissions are
;;  finally adjusted since it won't have execution permissions.
get_end_addr:
  call _get_ret_addr
  add rax, 0x5
  ret

;; A canary to found the end of .text section when extracting the shellcode
_end_shc:
  db 'E', 'N', 'D', 'S', 'H', 'C'
