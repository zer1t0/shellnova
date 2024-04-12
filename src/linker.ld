
SECTIONS
{
  . = 0x10000; /* start .text in 0x10000 to avoid errors with header segment */
  .text : {
        *start.asm* (.text$start)
        *.c.o*(.text*)
        *syscall_z.asm*(.text)
        *(.data*)
        *(.rdata*)
        *(.rodata*)
        *start.asm*(.text$end)
  }
}
