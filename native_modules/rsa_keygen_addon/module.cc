// some openssl wrappers to extend RSA support
#include "module.h"

namespace extcrypto
{

NAN_MODULE_INIT(InitModule)
{
    Set(target, New<String>("generateRsaPrivateKey").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(GenerateRsaPrivateKey)).ToLocalChecked());
    Set(target, New<String>("extractRsaPublicKey").ToLocalChecked(),
        GetFunction(New<FunctionTemplate>(ExtractRsaPublicKey)).ToLocalChecked());
}

NODE_MODULE(NODE_GYP_MODULE_NAME, InitModule)

} // namespace extcrypto