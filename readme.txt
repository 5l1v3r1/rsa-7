
[ generate key pair

  openssl genrsa -out private.pem 1024
  openssl rsa -in private.pem -pubout -out public.pem

[ signing
  
  openssl dgst -sha256 -sign private.pem -out rsa_tool.sig rsa_tool.exe
  openssl base64 -in rsa_tool.sig -out rsa_tool.asc
  
[ verify

  openssl base64 -d -in readme.sig.txt -out readme.sig
  openssl dgst -sha256 -verify public.pem -signature readme.sig readme.txt
  
ifinee  