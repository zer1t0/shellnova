# shellnova

A base project to create shellcodes from c code in an "easy" way.

The project compiles a c binary that includes all the machine code and data
into the .text section. Then the .text section its extracted to create a
shellcode.

A similar process is done in the more advanced
[Stardust](https://github.com/Cracked5pider/Stardust) project.

Additionally, shellnova dynamically allows to search the libc functions so it
can be accessed from the shellcode. It is possible to expand to search for
other library symbols if you need.

## Example

You can test the shellcode with the `utils/exec-shc` program:
```
cd shellnova/
make
utils/exec-shc shc.bin
```

And it should print something like:
```
Hello world
0x70e7876a50a0
0x70e7876a53e0
```

## Relevant Parts

- `src/linker.ld`: The linker script, which indicates that the data and code of
the final binary is going to be stored in the .text section.

- `src/main.c` is were your code goes.

- `src/lib_d.c` file includes the code for searching a library symbols.

- `src/libc_d.c` file includes the code for declaring libc symbols, it can
be expanded to include new symbols.

## Dependencies

In order to use the project you require the following dependencies:
```
sudo apt update
sudo apt install -y gcc cmake make nasm python3-pip
pip install -r scripts/requirements.txt
```
