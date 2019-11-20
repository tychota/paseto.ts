#include "public_key_crypto.h"

std::string extract_rsa_public_key(const std::string &private_key)
{
    char *private_key_buffer = strdup(private_key.c_str());

    BIO *bio = BIO_new(BIO_s_mem());
    RSA *rsa = RSA_new();

    BIO_write(bio, private_key_buffer, strlen(private_key_buffer));
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    PEM_write_bio_RSAPublicKey(bio, rsa);

    auto public_key_len = (uint64_t)BIO_pending(bio);
    auto public_key_buffer = (char *)calloc(public_key_len + 1, 1);

    // if (!public_key_buffer || (public_key_len == UINT64_MAX))
    // {
    //     free(public_key_buffer); // in case compiler dependent behavior for calloc after overflow returns a non-null pointer
    //     throw std::overflow_error("Unable to compute buffer");
    // }

    BIO_read(bio, public_key_buffer, public_key_len);

    BIO_vfree(bio);
    RSA_free(rsa);

    // return
    std::string public_key(public_key_buffer);
    free(public_key_buffer);
    free(private_key_buffer);
    return public_key;
}