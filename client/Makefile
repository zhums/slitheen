CFLAGS=-g -Wall

TARGETS= socks

all: $(TARGETS)

socks5proxy.o crypto.o tagging.o ptwist168.o:: socks5proxy.h crypto.h tagging.h ptwist.h

socks: socks5proxy.o crypto.o tagging.o ptwist168.o ptwist.h tagging.h crypto.h socks5proxy.h
	gcc -o $@ $^ -lpthread -lssl -lcrypto

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)
