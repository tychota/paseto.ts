#pragma once

#include <nan.h>

#include "private_key_crypto.h"

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

class RSAPrivateKeyGenWorker : public AsyncWorker
{
public:
    RSAPrivateKeyGenWorker();
    ~RSAPrivateKeyGenWorker();
    void Execute();
    void HandleOKCallback();
    void HandleErrorCallback();

private:
    char *private_key;
};

NAN_METHOD(GenerateRsaPrivateKey);
