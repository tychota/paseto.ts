#pragma once

#include <string>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

std::string extract_rsa_public_key(const std::string &private_key);