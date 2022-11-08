all: ipsec_all

ipsec_all: ipsec.o utility.o
	gcc ipsec.o utility.o -lcrypto -lssl -o ipsec_all
ipsec.o: ipsec.c
	gcc -c ipsec.c
util.o: util.c
	gcc -c utility.c
clean:
	rm *.o ipsec_all
