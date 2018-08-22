msvc:
	cl /DCAPI /O2 /Os rsa_tool.c rsa.c crypt32.lib
all: 
	gcc -Wall -O2 -Os rsa_tool.c rsa.c -orsa_tool -lcrypto				
clean:
	rm *.obj *.o	