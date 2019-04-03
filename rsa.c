/**
  Copyright (C) 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include "rsa.h"

#ifdef CAPI
void bin2hex(void *in, int len) {

  DWORD outlen=0;
  int ofs = 0;
  LPTSTR out;
  
  if (ofs==0) printf("\n");
  
  ofs += len;
  
  if (CryptBinaryToString(
      in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
      NULL, &outlen))
  {
    out = malloc(outlen);
    if (out!=NULL)
    {
      if (CryptBinaryToString(
          in, len, CRYPT_STRING_HEXASCIIADDR | CRYPT_STRING_NOCR,
          out, &outlen))
      {
        printf ("%s", out);
      }
      free(out);
    }      
  }
  putchar('\n');  
}

// used to convert digital signature from big-endian to little-endian
void byte_swap(void *buf, int len) {
    int     i;
    uint8_t t, *p=(uint8_t*)buf;
    
    for(i=0; i<len/2; i++) {
      t = p[i]; 
      p[i] = p[len - 1 - i];
      p[len - 1 - i] = t;
    }
}

#endif

/**
 *
 * open CSP and return pointer to RSA object
 *
 */
RSA_CTX* RSA_open(void)
{
  RSA_CTX      *ctx=NULL;
  #ifdef CAPI
    HCRYPTPROV prov=0;
    
    if (CryptAcquireContext(&prov,
        NULL, NULL, CRYPTO_PROVIDER,
        CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
      ctx = malloc(sizeof(RSA_CTX));
      if (ctx != NULL) {
        ctx->prov = prov;
      }
    }
    return ctx;
  #else
    OpenSSL_add_all_digests();    
    ctx = (RSA_CTX*)malloc(sizeof(RSA_CTX));
    return ctx;
  #endif  
}

/**
 *
 * close CSP and release memory for RSA_CTX object
 *
 */
void RSA_close(RSA_CTX *ctx) {
  #ifdef CAPI
    if (ctx->hash != 0) {
      CryptDestroyHash(ctx->hash);
      ctx->hash = 0;
    }

    // release private key
    if (ctx->privkey != 0) {
      CryptDestroyKey(ctx->privkey);
      ctx->privkey = 0;
    }

    // release public key
    if (ctx->pubkey != 0) {
      CryptDestroyKey(ctx->pubkey);
      ctx->pubkey = 0;
    }

    // release csp
    if (ctx->prov != 0) {
      CryptReleaseContext(ctx->prov, 0);
      ctx->prov = 0;
    }
  #else
    EVP_PKEY_free(ctx->pkey); 
  #endif

  // release object
  free(ctx);  
}

/**
 *
 * generate new key pair of keyLen-bits
 *
 */
int RSA_genkey(RSA_CTX* ctx, int keyLen) {
  #ifndef CAPI
    BIGNUM *e=NULL;
    RSA    *rsa;
  #endif  
  int ok=0;  
  if (ctx==NULL) return 0;
      
  #ifdef CAPI
    // release public
    if (ctx->pubkey != 0) {
      CryptDestroyKey(ctx->pubkey);
      ctx->pubkey = 0;
    }

    // release private
    if (ctx->privkey != 0) {
      CryptDestroyKey(ctx->privkey);
      ctx->privkey = 0;
    }

    // generate key pair for signing
    ok = CryptGenKey(ctx->prov, AT_KEYEXCHANGE,
      (keyLen << 16) | CRYPT_EXPORTABLE,
      &ctx->privkey);
  #else
    BN_dec2bn(&e, "65537"); // public exponent
    rsa = RSA_new(); 
    
    if (RSA_generate_key_ex(rsa, keyLen, e, NULL)) {
      if ((ctx->pkey = EVP_PKEY_new()) != NULL) { 
        ok = EVP_PKEY_assign_RSA(ctx->pkey, rsa);
      }
    }
    BN_free(e);    
  #endif
  return ok;  
}

#ifdef CAPI
/**
 *
 * convert string to binary
 *
 */    
void* Base642Bin (
    const char *in, 
    int        inLen, 
    int        flags, 
    PDWORD     outLen) 
{
    void* out = NULL;
    
    // calculate how much space required
    if (CryptStringToBinary(in, inLen,
        flags, NULL, (PDWORD)outLen, NULL, NULL))
    {
      out = malloc(*outLen);
          
      if (out != NULL) {
        // decode base64    
        CryptStringToBinary(in, inLen,
            flags, out, (PDWORD)outLen, NULL, NULL);
      }
    }
    return out;
}

/**
 *
 * convert binary to string
 *
 */  
const char* Bin2Base64 (LPVOID in, DWORD inLen, DWORD flags) 
{
    DWORD  outLen;
    LPVOID out = NULL;
    
    // calculate space for string
    if (CryptBinaryToString(in, inLen, 
        flags, NULL, &outLen))
    {
      out = malloc(outLen);
      
      // convert it
      if (out != NULL) {
        CryptBinaryToString(in, inLen,  
            flags, out, &outLen);
      }
    }
    return out;
}  

/**
 *
 * write binary to file encoded in PEM format
 *
 * ifile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * RSA_CTX     : RSA_CTX object with public and private keys
 *
 */
int PEM_write_file(int pemType,
    const char* ofile, void* data, int dataLen)
{
    const char *s=NULL, *e=NULL, *b64=NULL;
    FILE       *out;
    int        ok=0;

    if (pemType == RSA_PRIVATE_KEY) {
      s = "-----BEGIN PRIVATE KEY-----\n";
      e = "-----END PRIVATE KEY-----\n";
    } else if (pemType == RSA_PUBLIC_KEY) {
      s = "-----BEGIN PUBLIC KEY-----\n";
      e = "-----END PUBLIC KEY-----\n";
    } else if (pemType == RSA_SIGNATURE) {
      s = "-----BEGIN RSA SIGNATURE-----\n";
      e = "-----END RSA SIGNATURE-----\n";
    }
    // crypto API uses little endian convention.
    // we need to swap bytes for signatures
    // since there's no standard storage format
    if (pemType == RSA_SIGNATURE) {
       byte_swap(data, dataLen);
    }    
    
    b64 = Bin2Base64(data, dataLen,
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCR);
 
    if (b64 != NULL) {
      out = fopen(ofile, "wb");

      if (out != NULL) {
        fwrite(s, strlen(s), 1, out);
        fwrite(b64, strlen(b64), 1, out);
        fwrite(e, strlen(e), 1, out);
        fclose(out);
        ok=1;
      }
    }  
    return ok;
}
    
/**
 *
 * read public or private key in PEM format
 *
 * ifile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * RSA_CTX : RSA_CTX object with public and private keys
 *
 */
void* PEM_read_file(
    int         pemType,
    const char* ifile, 
    PDWORD      binLen)
{
    FILE        *in;
    struct stat st;
    void        *pem=NULL, *bin=NULL;

    stat(ifile, &st);
    
    if (st.st_size==0) {
      return NULL;
    }

    // open PEM file
    in = fopen(ifile, "rb");

    if (in != NULL) {
      // allocate memory for data
      pem = malloc(st.st_size + 1);
      if (pem != NULL) {
        // read data
        fread(pem, 1, st.st_size, in);

        bin = Base642Bin(pem, strlen(pem),
            CRYPT_STRING_ANY, binLen);

        if (bin != NULL) {
          // crypto API uses little endian convention
          // swap bytes for signatures
          // since there's no standard storage format  
          if (pemType == RSA_SIGNATURE) {
             byte_swap(bin, *binLen);
          }
        }
        free(pem);
      }   
      fclose(in);
    }
    return bin;
}
  
#endif
/**
 *
 * read public or private key from PEM format
 *
 * ifile   : name of file to read PEM encoded key from
 * pemType : type of key being read
 * RSA_CTX : RSA_CTX object to hold keys
 *
 */
int RSA_read_key(RSA_CTX* ctx,
    const char* ifile, int pemType)
{
  int                       ok=0;
  #ifdef CAPI
    LPVOID                  derData, keyData;
    PCRYPT_PRIVATE_KEY_INFO pki = 0;
    DWORD                   pkiLen, derLen, keyLen;
 
    // decode base64 string
    derData = PEM_read_file(pemType, ifile, &derLen);

    if (derData != NULL) {
      // decode DER
      // is it a public key?
      if (pemType == RSA_PUBLIC_KEY) { 
        if (CryptDecodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, derData, derLen,
            CRYPT_DECODE_ALLOC_FLAG, NULL,
            &keyData, &keyLen))
        {
          // if decode ok, import into key object
          ok = CryptImportPublicKeyInfo(ctx->prov, 
             X509_ASN_ENCODING,
            (PCERT_PUBLIC_KEY_INFO)keyData, &ctx->pubkey);

          // release allocated memory
          LocalFree(keyData);
        }
      } else {
        // convert the PKCS#8 data to private key info
        if (CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO, derData, derLen,
            CRYPT_DECODE_ALLOC_FLAG,
            NULL, &pki, &pkiLen))
        {          
          // then convert the private key to private key blob
          if (CryptDecodeObjectEx(
              X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
              PKCS_RSA_PRIVATE_KEY,
              pki->PrivateKey.pbData,
              pki->PrivateKey.cbData,
              CRYPT_DECODE_ALLOC_FLAG, NULL,
              &keyData, &keyLen))
          {
            // if decode ok, import it
            ok = CryptImportKey(ctx->prov, keyData, keyLen,
                0, CRYPT_EXPORTABLE, &ctx->privkey);

            // release data
            LocalFree(keyData);
          }
          // release private key info
          LocalFree(pki);
        } 
      }
      free(derData);
    }
  #else
    FILE *fd = fopen(ifile, "rb");
  
    if (fd != NULL) {
      // private key for signing?
      if (pemType == RSA_PRIVATE_KEY) {
        ctx->pkey = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
      // public key for verifying?  
      } else if (pemType == RSA_PUBLIC_KEY) {
        ctx->pkey = PEM_read_PUBKEY(fd, NULL, NULL, NULL);
      }
      ok = (ctx->pkey != NULL);
      fclose(fd);
    }
  #endif    
    return ok;
}

/**
 *
 * save public or private key to PEM format
 *
 * ofile   : name of file to write PEM encoded key
 * pemType : type of key being saved
 * RSA_CTX : RSA_CTX object with public and private keys
 *
 */
int RSA_write_key(RSA_CTX* ctx,
    const char* ofile, int pemType)
{
  int      ok=0;
  
  #ifdef CAPI
    DWORD  pkiLen, derLen;
    LPVOID pki, derData;

    // public key?
    if (pemType == RSA_PUBLIC_KEY)
    {
      // get size of public key info
      if (CryptExportPublicKeyInfo(ctx->prov, 
          AT_KEYEXCHANGE,
          X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
          NULL, &pkiLen))
      {
        // allocate memory
        pki = malloc(pkiLen);

        // export public key info
        if (CryptExportPublicKeyInfo(ctx->prov, 
            AT_KEYEXCHANGE,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            pki, &pkiLen))
        {
          // get size of DER encoding
          if (CryptEncodeObjectEx(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO, pki, 0,
            NULL, NULL, &derLen))
          {
            derData = malloc(derLen);
            if (derData) {
              // convert to DER format
              ok = CryptEncodeObjectEx(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                X509_PUBLIC_KEY_INFO, pki, 0,
                NULL, derData, &derLen);

                // write to PEM file
                if (ok) {
                  PEM_write_file(RSA_PUBLIC_KEY, 
                      ofile, derData, derLen);
              }
            }
            free(derData);            
          }
        }
      }
    } else {
      // get length of PKCS#8 encoding
      if (CryptExportPKCS8(ctx->prov, 
          AT_KEYEXCHANGE, szOID_RSA_RSA, 
          0, NULL, NULL, &pkiLen))
      {
        pki = malloc(pkiLen);

        if (pki != NULL) {
          // export the private key
          ok = CryptExportPKCS8(ctx->prov, 
            AT_KEYEXCHANGE, szOID_RSA_RSA, 
            0x8000, NULL, pki, &pkiLen);

          // write key to PEM file
          if (ok) {
            PEM_write_file(RSA_PRIVATE_KEY, 
                ofile, pki, pkiLen);
          }
          free(pki);
        }
      }
    }
    #else
      FILE *fd = fopen(ofile, "wb");
      if (fd != NULL) {
        if (pemType == RSA_PUBLIC_KEY) {
          ok = PEM_write_PUBKEY(fd, ctx->pkey);
        } else if (pemType == RSA_PRIVATE_KEY) {        
          ok = PEM_write_PKCS8PrivateKey(fd, 
              ctx->pkey, NULL, NULL, 0, NULL, NULL);   
        }
        fclose(fd);
      }        
    #endif
    return ok;
}

#ifdef CAPI
/**
 *
 *         calculate sha256 hash of file
 *
 * ifile : contains data to generate hash for
 * RSA_CTX   : RSA_CTX object with HCRYPTHASH object
 *
 */
int SHA256_hash(
    RSA_CTX* ctx, 
    const char* ifile)
{
    FILE *fd;
    BYTE buf[BUFSIZ];
    int  len, ok = 0;

    // 1. destroy hash object if already created
    if (ctx->hash != 0) {
      CryptDestroyHash(ctx->hash);
      ctx->hash = 0;
    }

    // 2. try open the file for reading
    fd = fopen(ifile, "rb");
    if (fd == NULL) return 0;
    
    // 3. create hash object
    if (CryptCreateHash (ctx->prov,
      CRYPTO_HASH, 0, 0, &ctx->hash))
    {
      // 4. hash file contents
      for(;;) {
        len = fread(buf, 1, BUFSIZ, fd);
        if(len == 0) break;
        
        ok = CryptHashData (ctx->hash, buf, len, 0);
        if (!ok) break;
      }
    }
    fclose(fd);
    
    return ok;
}

#endif

/**
 *
 *          create a signature for file using RSA private key
 *
 * sfile   : output file of RSA signature
 * ifile   : input file of data to generate signature for
 * RSA_CTX : RSA_CTX object with private key
 *
 */
int RSA_sign_file(
    RSA_CTX* ctx,
    const char* ifile, 
    const char* sfile)
{
  int      ok=0;
  #ifdef CAPI
    DWORD  sigLen=0;
    LPVOID sig;
    FILE   *out;

    // 1. try open file for signature
    out = fopen(sfile, "wb");
    if (out != NULL) { 
      // 2. calculate sha256 hash for file
      if (SHA256_hash(ctx, ifile)) {
        // 3. acquire length of signature
        if (CryptSignHash (ctx->hash, 
            AT_KEYEXCHANGE, NULL, 0, 
            NULL, &sigLen)) {
          sig = malloc (sigLen);
          if (sig != NULL) {
            // 4. obtain signature
            if (CryptSignHash (ctx->hash, 
                AT_KEYEXCHANGE, NULL, 0, 
                sig, &sigLen))
            {
              // 5. convert signature to big-endian format
              byte_swap(sig, sigLen);
              ok = 1;
              // 6. save signature to file
              fwrite(sig, 1, sigLen, out);
            }
            free(sig);
          }
        }
      }
      fclose(out);
    }
  #else
    FILE       *fd, *out;
    EVP_MD_CTX *md;
    uint8_t    *sig;
    uint32_t   sigLen, bufLen;
    uint8_t    buf[BUFSIZ];

    // 1. try open file for reading 
    fd = fopen(ifile, "rb");
    
    if (fd != NULL) {
      // 2. try open file for signature
      out = fopen(sfile, "wb");
      if (out != NULL) {
        // 3. create digest object
        md = EVP_MD_CTX_create();
        if (md != NULL) {
          // 4. allocate memory for signature
          sigLen = EVP_PKEY_size(ctx->pkey);
          sig    = malloc(sigLen);
        
          if (sig != NULL) {
            // 5. initialize signing context
            if (EVP_SignInit_ex(md, EVP_sha256(), NULL)) {
              // 6. derive a sha-256 hash from file data
              for (;;) {
                bufLen = fread(buf, 1, BUFSIZ, fd);
                if (bufLen == 0) break;
      
                EVP_SignUpdate(md, buf, bufLen);
              }
              // 7. obtain the signature
              EVP_SignFinal(md, sig, &sigLen, ctx->pkey);
              // 8. save signature to file
              ok = 1;
              fwrite(sig, 1, sigLen, out);
            }
            free(sig);
          }
          EVP_MD_CTX_destroy(md);
        }
        fclose(out);
      }
      fclose(fd);
    }   
  #endif        
    return ok;
}

/**
 *
 *         verify a signature using public key
 *
 * sfile   : file with signature 
 * ifile   : file with data to verify signature for
 * RSA_CTX : RSA_CTX object with public key
 *
 */
int RSA_verify_file(
    RSA_CTX*    ctx,
    const char* ifile, 
    const char* sfile)
{
    int    ok=0;
  #ifdef CAPI
    DWORD  sigLen;
    BYTE   sig[MAX_RSA_BYTES];
    FILE   *in;

    // 1. read signature from file
    in = fopen(sfile, "rb");
    if (in==NULL) return 0;
    sigLen = fread(sig, 1, MAX_RSA_BYTES, in);
    fclose(in);

    // 2. convert signature from big-endian to little-endian format
    byte_swap(sig, sigLen);
    
    // 3. calculate sha256 hash of file
    if (SHA256_hash(ctx, ifile)) {
      // 4. verify signature using public key
      ok = CryptVerifySignature (ctx->hash, sig,
            sigLen, ctx->pubkey, NULL, 0);
    }
  #else
    FILE       *fd, *in;
    EVP_MD_CTX *md;
    uint8_t    sig[MAX_RSA_BYTES];
    int        sigLen=0, bufLen;
    uint8_t    buf[BUFSIZ];

    // 1. read signature from file
    in = fopen(sfile, "rb");
    if (in==NULL) return 0;
    sigLen = fread(sig, 1, MAX_RSA_BYTES, in);
    fclose(in);

    // 2. open input file for reading
    fd = fopen(ifile, "rb");
    
    if (fd != NULL) {
      // 3. create message digest context
      md = EVP_MD_CTX_create();
      if (md != NULL) {
        // 4. initialize for SHA-256
        if (EVP_VerifyInit_ex(md, EVP_sha256(), NULL)) {
          // 5. hash data in file
          for (;;) {
            bufLen = fread(buf, 1, BUFSIZ, fd);
            if (bufLen == 0) break;
      
            EVP_VerifyUpdate(md, buf, bufLen);
          }
          // 6. good signature?
          ok = EVP_VerifyFinal(md, sig, sigLen, ctx->pkey);
        }
        EVP_MD_CTX_destroy(md);
      }
      fclose(fd); // close input file descriptor
    }       
  #endif    
    return ok;
}
