.PHONY: all

all: shc.bin exec-shc inject-shc

shc.bin: src/*
	cmake --preset x64-shellcode
	cmake --build out/build/x64-shellcode/
	cp out/build/x64-shellcode/shc.bin .

exec-shc:
	$(MAKE) -C utils/exec-shc

inject-shc:
	$(MAKE) -C utils/inject-shc
