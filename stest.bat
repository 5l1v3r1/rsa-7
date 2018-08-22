rsa_tool -g1024
openssl rsa -text -inform PEM -in public.pem -pubin
openssl rsa -text -inform PEM -in private.pem
openssl dgst -sha256 -sign private.pem -out sig.bin rsa_tool.exe
openssl dgst -sha256 -verify public.pem -signature sig.bin rsa_tool.exe
rsa_tool -v public.pem -x sig.bin rsa_tool.exe
rsa_tool -s private.pem -x sig.bin rsa_tool.exe
openssl dgst -sha256 -verify public.pem -signature sig.bin rsa_tool.exe