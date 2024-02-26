.PHONY: all
all: RC4 RC4Attacker

RC4:  RC4.c
	gcc -o RC4 RC4.c -lm

RC4Attacker: RC4Attacker.c
	gcc -o RC4Attacker RC4Attacker.c -lm -pthread

.PHONY: clean
clean:
	-rm RC4 RC4Attacker
