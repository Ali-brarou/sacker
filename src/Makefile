CC 	= 	gcc
CFLAGS = 	-Wall -Wextra

all: sacker

sacker: main.c
	$(CC) main.c $(CFLAGS) -o $@

sample: sample.c
	$(CC) sample.c -o $@

stub: stub.asm 
	nasm -felf64 stub.asm -o stub.o -O0
	ld stub.o -o stub -pie -O0

.PHONY: clean 
clean: 
	@rm -rf sacker sample sample_packed stub.o stub

