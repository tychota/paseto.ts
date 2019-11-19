const rsaKeygen = require('../../build/Release/rsa_keygen_addon');

const generateKey = async () => {
  const privatekey = await rsaKeygen.generateRsaPrivateKey();
  console.log(privatekey);

  const publicKey = await rsaKeygen.extractRsaPublicKey(privatekey);
  console.log(publicKey);
};

generateKey();
