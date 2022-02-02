all: PICOServer

clean:
	@rm -rf *.o
	@rm -rf PICOServer

PICOServer: main.o httpd.o
	gcc -o PICOServer $^

main.o: main.c httpd.h
	gcc -c -o main.o main.c

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c
