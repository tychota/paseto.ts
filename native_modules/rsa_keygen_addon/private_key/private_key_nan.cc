
#include "private_key_nan.h"

RSAPrivateKeyGenWorker::RSAPrivateKeyGenWorker() : AsyncWorker(nullptr) {}
RSAPrivateKeyGenWorker::~RSAPrivateKeyGenWorker()
{
}

void RSAPrivateKeyGenWorker::Execute()
{
    this->private_key = generate_rsa_private_key();
    if (this->private_key == nullptr)
    {
        SetErrorMessage("Unable to generate key");
    }
}

void RSAPrivateKeyGenWorker::HandleOKCallback()
{
    HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    promise->Resolve(GetCurrentContext(), New(this->private_key).ToLocalChecked());
    v8::Isolate::GetCurrent()->RunMicrotasks();

    free(private_key);
}

void RSAPrivateKeyGenWorker::HandleErrorCallback()
{
    HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
    promise->Reject(GetCurrentContext(), New(this->ErrorMessage()).ToLocalChecked());
    v8::Isolate::GetCurrent()->RunMicrotasks();

    free(private_key);
}

NAN_METHOD(GenerateRsaPrivateKey)
{
    auto worker = new RSAPrivateKeyGenWorker();
    auto resolver = v8::Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}