#include "private_key_crypto.h"

char *generate_rsa_private_key()
{
    // begin keygen
    BIGNUM *exponent = BN_new();
    BN_set_word(exponent, RSA_F4); // 65537

    RSA *rsa = RSA_new();
    int64_t key_generated = RSA_generate_key_ex(rsa, 2048, exponent, NULL);

    if (!key_generated)
    {
        return nullptr;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    uint64_t private_key_len = BIO_pending(bio);
    char *private_key = (char *)calloc(private_key_len + 1, 1);

    if (!private_key || (private_key_len == UINT64_MAX))
    {
        free(private_key); // in case compiler dependent behavior for calloc after overflow returns a non-null pointer
        return nullptr;
    }

    BIO_read(bio, private_key, private_key_len);

    BIO_vfree(bio);
    RSA_free(rsa);
    BN_free(exponent);

    // return
    return private_key;
}