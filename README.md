
## About ##

rsa_tool provides a working example in C of how to use Microsoft Crypto API to digitally sign and verify the integrity of files using the RSA digital signature algorithm.

The private and public keys must be stored in PEM (Privacy Exchange Mail) format.
Signatures are stored as binary using big-endian convention.

See more info about tool and how it works [here](https://stosd.wordpress.com/2017/04/22/capi-openssl/)

## Building ##

For Linux/BSD, just type 'make all'
For Microsoft Visual Studio, type: 'nmake'

If you receive any errors for Linux/BSD like missing headers, it's because libssl-dev is missing.
Install with package manager and retry.

* **MSVC**

	cl /DCAPI /O2 /Os rsa_tool.c rsa.c

* **Mingw**
	
	gcc -DCAPI -O2 -Os rsa_tool.c rsa.c -orsa_tool -lcrypt32 -lshlwapi 

* **Linux/BSD**

	gcc -O2 -Os rsa_tool.c rsa.c -orsa_tool -lcrypto


## Usage ##

* **Generating RSA Key**
 
  ./rsa_tool -s private.pem -v public.pem -g 2048

* **Signing a file**

  ./rsa_tool -s private.pem rsa_tool -x sig.bin

* **Verifying a file**

  ./rsa_tool -v public.pem rsa_tool -x sig.bin
