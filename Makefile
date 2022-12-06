CFLAGS := -Wall -std=c99 -g

all: main.o sha1.o
	gcc $(CFLAGS) main.o sha1.o

main.o: main.c
	gcc $(CFLAGS) -c main.c

sha1.o: sha1.c sha1.h
	gcc $(CFLAGS) -c sha1.c
