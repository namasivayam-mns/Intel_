#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

#ifdef WIN
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "openssl.lib")
#endif // WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES       = 10000;
static constexpr size_t HASH_SIZE_BYTES             = 32; // SHA-256 output size
static constexpr size_t IV_SIZE_BYTES               = 12; // Size for AES-GCM IV
static constexpr size_t GMAC_SIZE_BYTES             = 16; // Size for GCM authentication tag

bool CryptoWrapper::hmac_SHA256(const BYTE* key, size_t keySizeBytes, const BYTE* message, size_t messageSizeBytes, BYTE* macBuffer, size_t macBufferSizeBytes) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("EVP_MD_CTX_new failed on HMAC\n");
        goto err;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, keySizeBytes);
    if (!pkey) {
        printf("EVP_PKEY_new_raw_private_key failed on HMAC\n");
        goto err;
    }

    if (!EVP_DigestSignInit(ctx, NULL, EVP_get_digestbyname("SHA256"), NULL, pkey)) {
        printf("EVP_DigestSignInit failed on HMAC\n");
        goto err;
    }

    if (!EVP_DigestSignUpdate(ctx, message, messageSizeBytes)) {
        printf("EVP_DigestSignUpdate for message failed on HMAC\n");
        goto err;
    }

    if (!EVP_DigestSignFinal(ctx, macBuffer, &macBufferSizeBytes)) {
        printf("EVP_DigestSignFinal failed on HMAC\n");
        goto err;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;

err:
    printf("Error 0x%lx\n", ERR_get_error());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
}

bool CryptoWrapper::deriveKey_HKDF_SHA256(const BYTE* salt, size_t saltSizeBytes, const BYTE* secretMaterial, size_t secretMaterialSizeBytes, const BYTE* context, size_t contextSizeBytes, BYTE* outputBuffer, size_t outputBufferSizeBytes) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        printf("failed to get HKDF context\n");
        goto err;
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes) <= 0 ||
        EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes) <= 0) {
        printf("Error in deriving key with HKDF\n");
        goto err;
    }

    EVP_PKEY_CTX_free(pctx);
    return true;

err:
    EVP_PKEY_CTX_free(pctx);
    return false;
}

size_t CryptoWrapper::getCiphertextSizeAES_GCM256(size_t plaintextSizeBytes) {
    return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}

size_t CryptoWrapper::getPlaintextSizeAES_GCM256(size_t ciphertextSizeBytes) {
    return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(const BYTE* key, size_t keySizeBytes, const BYTE* plaintext, size_t plaintextSizeBytes, const BYTE* aad, size_t aadSizeBytes, BYTE* ciphertextBuffer, size_t ciphertextBufferSizeBytes, size_t* pCiphertextSizeBytes) {
    BYTE iv[IV_SIZE_BYTES];
    BYTE mac[GMAC_SIZE_BYTES];
    size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);

    if ((!plaintext || !plaintextSizeBytes) && (!aad || !aadSizeBytes)) return false;
    if (!ciphertextBuffer || !ciphertextBufferSizeBytes) {
        if (pCiphertextSizeBytes) {
            *pCiphertextSizeBytes = ciphertextSizeBytes;
            return true;
        } else {
            return false;
        }
    }

    if (ciphertextBufferSizeBytes < ciphertextSizeBytes) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error in creating a CIPHER context at encryption\n");
        goto end;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL) ||
        !EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) ||
        !EVP_EncryptUpdate(ctx, NULL, &len, aad, aadSizeBytes) ||
        !EVP_EncryptUpdate(ctx, ciphertextBuffer, &len, plaintext, plaintextSizeBytes) ||
        !EVP_EncryptFinal_ex(ctx, ciphertextBuffer + len, &len) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GMAC_SIZE_BYTES, mac)) {
        printf("Error in AES GCM encryption\n");
        goto end;
    }

    memcpy(ciphertextBuffer + len, mac, GMAC_SIZE_BYTES);
    if (pCiphertextSizeBytes) *pCiphertextSizeBytes = ciphertextSizeBytes;

    EVP_CIPHER_CTX_free(ctx);
    return true;

end:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool CryptoWrapper::decryptAES_GCM256(const BYTE* key, size_t keySizeBytes, const BYTE* ciphertext, size_t ciphertextSizeBytes, const BYTE* aad, size_t aadSizeBytes, BYTE* plaintextBuffer, size_t plaintextBufferSizeBytes, size_t* pPlaintextSizeBytes) {
    if (!ciphertext || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES)) return false;

    size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);
    if (!plaintextBuffer || !plaintextBufferSizeBytes) {
        if (pPlaintextSizeBytes) {
            *pPlaintextSizeBytes = plaintextSizeBytes;
            return true;
        } else {
            return false;
        }
    }

    if (plaintextBufferSizeBytes < plaintextSizeBytes) return false;

    BYTE iv[IV_SIZE_BYTES];
    BYTE mac[GMAC_SIZE_BYTES];
    memcpy(mac, ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES, GMAC_SIZE_BYTES);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Error in creating a CIPHER context at decryption\n");
        goto end;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE_BYTES, NULL) ||
        !EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) ||
        !EVP_DecryptUpdate(ctx, NULL, &len, aad, aadSizeBytes) ||
        !EVP_DecryptUpdate(ctx, plaintextBuffer, &len, ciphertext, ciphertextSizeBytes) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, mac) ||
        !EVP_DecryptFinal_ex(ctx, plaintextBuffer + len, &len)) {
        printf("Error in AES GCM decryption\n");
        goto end;
    }

    if (pPlaintextSizeBytes) *pPlaintextSizeBytes = plaintextSizeBytes;

    EVP_CIPHER_CTX_free(ctx);
    return true;

end:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool CryptoWrapper::readRSAKeyFromFile(const char* keyFilename, const char* filePassword, KeypairContext** pKeyContext) {
    BIO* bio = BIO_new_file(keyFilename, "rb");
    if (!bio) {
        printf("Error in reading file at readRSAKeyFromFile\n");
        goto end;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, (void*)filePassword, NULL, NULL);
    if (!pkey) {
        printf("Error in reading pkey from bio at readRSAKeyFromFile\n");
        goto end;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        printf("Error in creating key context at readRSAKeyFromFile\n");
        goto end;
    }

    *pKeyContext = ctx;
    BIO_free(bio);
    return true;

end:
    BIO_free(bio);
    return false;
}

bool CryptoWrapper::signMessageRsa3072Pss(const BYTE* key, size_t keySizeBytes, const BYTE* message, size_t messageSizeBytes, BYTE* signatureBuffer, size_t* signatureBufferSizeBytes) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("Error in creating digest context at signMessageRsa3072Pss\n");
        goto end;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_RSA, NULL, key, keySizeBytes);
    if (!pkey) {
        printf("Error in creating private key at signMessageRsa3072Pss\n");
        goto end;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, pkey) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mdctx), RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(mdctx), -1) <= 0 ||
        EVP_DigestSignUpdate(mdctx, message, messageSizeBytes) <= 0 ||
        EVP_DigestSignFinal(mdctx, signatureBuffer, signatureBufferSizeBytes) <= 0) {
        printf("Error in signing message at signMessageRsa3072Pss\n");
        goto end;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return true;

end:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return false;
}

bool CryptoWrapper::verifyMessageRsa3072Pss(const BYTE* key, size_t keySizeBytes, const BYTE* message, size_t messageSizeBytes, const BYTE* signature, size_t signatureSizeBytes) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("Error in creating digest context at verifyMessageRsa3072Pss\n");
        goto end;
    }

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_RSA, NULL, key, keySizeBytes);
    if (!pkey) {
        printf("Error in creating public key at verifyMessageRsa3072Pss\n");
        goto end;
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha384(), NULL, pkey) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(EVP_MD_CTX_pkey_ctx(mdctx), RSA_PKCS1_PSS_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_MD_CTX_pkey_ctx(mdctx), -1) <= 0 ||
        EVP_DigestVerifyUpdate(mdctx, message, messageSizeBytes) <= 0 ||
        EVP_DigestVerifyFinal(mdctx, signature, signatureSizeBytes) <= 0) {
        printf("Error in verifying message at verifyMessageRsa3072Pss\n");
        goto end;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return true;

end:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return false;
}

bool CryptoWrapper::startDh(BYTE** ppDhParamsBuffer, size_t* pDhParamsBufferSize, BYTE** ppPubKeyBuffer, size_t* pPubKeyBufferSize, KeypairContext** ppKeypairContext) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx || EVP_PKEY_paramgen_init(pctx) <= 0 || EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe2048) <= 0 || EVP_PKEY_paramgen(pctx, &dhparams) <= 0) {
        printf("Error in starting DH\n");
        goto end;
    }

    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new(dhparams, NULL);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &keypair) <= 0) {
        printf("Error in starting DH key generation\n");
        goto end;
    }

    if (!writePublicKeyToPemBuffer(keypair, ppPubKeyBuffer, pPubKeyBufferSize)) {
        printf("Error in writing DH public key to buffer\n");
        goto end;
    }

    if (!EVP_PKEY_print_params(bio, keypair, 0, NULL)) {
        printf("Error in printing DH parameters\n");
        goto end;
    }

    *ppKeypairContext = kctx;
    EVP_PKEY_CTX_free(pctx);
    return true;

end:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    return false;
}

bool CryptoWrapper::generateDhParameters(BYTE** ppDhParamsBuffer, size_t* pDhParamsBufferSize) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) {
        printf("Error in creating DH context at generateDhParameters\n");
        goto end;
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0 || EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe2048) <= 0 || EVP_PKEY_paramgen(pctx, &dhparams) <= 0) {
        printf("Error in generating DH parameters\n");
        goto end;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        printf("Error in creating BIO at generateDhParameters\n");
        goto end;
    }

    if (!PEM_write_bio_Parameters(bio, dhparams)) {
        printf("Error in writing DH parameters to BIO\n");
        goto end;
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    *ppDhParamsBuffer = (BYTE*)malloc(bptr->length);
    memcpy(*ppDhParamsBuffer, bptr->data, bptr->length);
    *pDhParamsBufferSize = bptr->length;

    BIO_free(bio);
    EVP_PKEY_free(dhparams);
    return true;

end:
    EVP_PKEY_CTX_free(pctx);
    return false;
}

bool CryptoWrapper::writePublicKeyToPemBuffer(EVP_PKEY* pkey, BYTE** ppPubKeyBuffer, size_t* pPubKeyBufferSize) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio_PUBKEY(bio, pkey)) {
        printf("Error in writing public key to buffer\n");
        goto end;
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(bio, &bptr);
    *ppPubKeyBuffer = (BYTE*)malloc(bptr->length);
    memcpy(*ppPubKeyBuffer, bptr->data, bptr->length);
    *pPubKeyBufferSize = bptr->length;

    BIO_free(bio);
    return true;

end:
    BIO_free(bio);
    return false;
}

bool CryptoWrapper::loadPublicKeyFromPemBuffer(const BYTE* pPubKeyBuffer, size_t pubKeyBufferSize, EVP_PKEY** ppPubKey) {
    BIO* bio = BIO_new_mem_buf(pPubKeyBuffer, pubKeyBufferSize);
    if (!bio || !PEM_read_bio_PUBKEY(bio, ppPubKey, NULL, NULL)) {
        printf("Error in reading public key from buffer\n");
        goto end;
    }

    BIO_free(bio);
    return true;

end:
    BIO_free(bio);
    return false;
}

void CryptoWrapper::cleanKeyContext(KeypairContext* pKeyContext) {
    EVP_PKEY_CTX_free(pKeyContext);
}
#endif 
