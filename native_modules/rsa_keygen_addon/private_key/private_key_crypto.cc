#include "private_key_crypto.h"

char *generate_rsa_private_key()
{
    // begin keygen
    auto exponent = BN_new();
    BN_set_word(exponent, RSA_F4); // 65537

    auto rsa = RSA_new();
    auto key_generated = RSA_generate_key_ex(rsa, 2048, exponent, NULL);

    if (!key_generated)
    {
        return nullptr;
    }

    auto bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    auto private_key_len = (uint64_t)BIO_pending(bio);
    auto private_key = (char *)calloc(private_key_len + 1, 1);

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