#pragma once

#include <nan.h>

#include "public_key_crypto.h"

using Nan::AsyncWorker;
using Nan::GetCurrentContext;
using Nan::HandleScope;
using Nan::New;
using Nan::Null;
using Nan::To;
using v8::Local;
using v8::Promise;
using v8::String;
using v8::Value;

class RSAPublicKeyExtractWorker : public AsyncWorker
{
public:
    RSAPublicKeyExtractWorker(std::string private_key);
    ~RSAPublicKeyExtractWorker();
    void Execute();
    void HandleOKCallback();
    void HandleErrorCallback();

private:
    std::string private_key;
    std::string public_key;
};

NAN_METHOD(ExtractRsaPublicKey);