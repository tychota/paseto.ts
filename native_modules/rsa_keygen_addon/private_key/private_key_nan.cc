
#include "private_key_nan.h"

RSAPrivateKeyGenWorker::RSAPrivateKeyGenWorker() : AsyncWorker(nullptr) {}
RSAPrivateKeyGenWorker::~RSAPrivateKeyGenWorker() {}

void RSAPrivateKeyGenWorker::Execute()
{
    this->private_key = generate_rsa_private_key();
}

void RSAPrivateKeyGenWorker::HandleOKCallback()
{
    HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-result"
    promise->Resolve(GetCurrentContext(), New(this->private_key).ToLocalChecked());
#pragma clang diagnostic pop
    v8::Isolate::GetCurrent()->RunMicrotasks();
}

void RSAPrivateKeyGenWorker::HandleErrorCallback()
{
    HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-result"
    promise->Reject(GetCurrentContext(), New(this->ErrorMessage()).ToLocalChecked());
#pragma clang diagnostic pop
    v8::Isolate::GetCurrent()->RunMicrotasks();
}

NAN_METHOD(GenerateRsaPrivateKey)
{
    auto worker = new RSAPrivateKeyGenWorker();
    auto resolver = v8::Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}