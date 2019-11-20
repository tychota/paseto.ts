
#include "public_key_nan.h"

RSAPublicKeyExtractWorker::RSAPublicKeyExtractWorker(std::string private_key) : AsyncWorker(nullptr), private_key(private_key) {}
RSAPublicKeyExtractWorker::~RSAPublicKeyExtractWorker() {}

void RSAPublicKeyExtractWorker::Execute()
{
    this->public_key = extract_rsa_public_key(private_key);
}

void RSAPublicKeyExtractWorker::HandleOKCallback()
{
    HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-result"
    promise->Resolve(GetCurrentContext(), New(this->public_key).ToLocalChecked());
#pragma clang diagnostic pop
    v8::Isolate::GetCurrent()->RunMicrotasks();
}

void RSAPublicKeyExtractWorker::HandleErrorCallback()
{
    HandleScope scope;

    auto promise = GetFromPersistent(1).As<Promise::Resolver>();
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-result"
    promise->Reject(GetCurrentContext(), New(this->ErrorMessage()).ToLocalChecked());
#pragma clang diagnostic pop
    v8::Isolate::GetCurrent()->RunMicrotasks();
}

NAN_METHOD(ExtractRsaPublicKey)
{
    auto private_key_string = To<String>(info[0]).ToLocalChecked();
    Nan::Utf8String private_key_utf8(private_key_string);
    std::string private_key(*private_key_utf8);

    auto worker = new RSAPublicKeyExtractWorker(private_key);
    auto resolver = v8::Promise::Resolver::New(Nan::GetCurrentContext()).ToLocalChecked();
    worker->SaveToPersistent(1, resolver);

    AsyncQueueWorker(worker);
    info.GetReturnValue().Set(resolver->GetPromise());
}
