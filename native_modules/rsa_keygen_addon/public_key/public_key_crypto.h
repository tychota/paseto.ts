#pragma once

#include <string>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

char *extract_rsa_public_key(std::string private_key);