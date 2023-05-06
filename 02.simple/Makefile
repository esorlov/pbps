all: HTTPSimple
clean:
	@rm -f *.o
	@rm -f HTTPSimple
	@rm -f HTTPSimple-cl
HTTPSimple: 
	gcc -o HTTPSimple HTTPSimple.c -lssl -lcrypto
	gcc -o HTTPSimple-cl HTTPSimple-cl.c -lssl -lcrypto
