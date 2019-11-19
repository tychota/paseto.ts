#include "public_key_crypto.h"

char *extract_rsa_public_key(std::string private_key_std)
{
    const char *private_key = private_key_std.c_str();

    BIO *bio = BIO_new(BIO_s_mem());
    RSA *rsa = RSA_new();

    BIO_write(bio, private_key, strlen(private_key));
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    PEM_write_bio_RSAPublicKey(bio, rsa);

    uint64_t public_key_len = BIO_pending(bio);
    char *public_key = (char *)calloc(public_key_len + 1, 1);

    if (!public_key || (public_key_len == UINT64_MAX))
    {
        free(public_key); // in case compiler dependent behavior for calloc after overflow returns a non-null pointer
        return nullptr;
    }

    BIO_read(bio, public_key, public_key_len);

    BIO_vfree(bio);
    RSA_free(rsa);

    // return
    return public_key;
}