TARGETS=client smtp

all: $(TARGETS)

.c.o:  ptwist.h slitheen.h crypto.h
	gcc -g -ggdb -c $< -o $@ -I../sslout/include

slitheen.o crypto.o ptwist168.o :: ptwist.h slitheen.h crypto.h

client: slitheen.o ptwist168.o crypto.o crypto.h ptwist.h slitheen.h
	gcc -g -ggdb -o $@ $^ client.c -I../sslout/include -L../sslout/lib -lssl -lcrypto -ldl -lpthread

smtp: slitheen.o ptwist168.o crypto.o crypto.h ptwist.h slitheen.h
	gcc -g -ggdb -o $@ $^ smtpClient.c -I../sslout/include -L../sslout/lib -lssl -lcrypto -ldl -lpthread

clean:
	-rm *.o

veryclean: clean
	-rm $(TARGETS)

