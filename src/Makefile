CC 	= 	gcc
CFLAGS = 	-Wall -Wextra

all: sacker

sacker: main.c
	$(CC) main.c $(CFLAGS) -o $@

sample: sample.c
	$(CC) sample.c -o $@

.PHONY: clean 
clean: 
	@rm -rf sacker sample

