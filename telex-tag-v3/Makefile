CFLAGS=-g -O3 -Wall

TARGETS=rserv rclient genkeys ptwist168

all: $(TARGETS)

ptwist168: ptwist168.c
	gcc $(CFLAGS) -DTESTING -o $@ $^

rserv.o rclient.o genkeys.o ptwist168.o:: ptwist.h

rserv: rserv.o ptwist168.o
	gcc -g -o $@ $^ -lssl -lcrypto

rclient: rclient.o ptwist168.o
	gcc -g -o $@ $^ -lssl -lcrypto

genkeys: genkeys.o ptwist168.o
	gcc -g -o $@ $^ -lssl -lcrypto

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)
	-rm privkey pubkey tags
