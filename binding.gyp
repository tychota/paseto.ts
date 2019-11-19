{
  "targets": [
    {
      "target_name": "rsa_keygen_addon",
      "sources": [
        "./native_modules/rsa_keygen_addon/module.cc",
        "./native_modules/rsa_keygen_addon/private_key/private_key_nan.cc",
        "./native_modules/rsa_keygen_addon/private_key/private_key_crypto.cc",
        "./native_modules/rsa_keygen_addon/public_key/public_key_nan.cc",
        "./native_modules/rsa_keygen_addon/public_key/public_key_crypto.cc"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ]
    }
  ]
}
