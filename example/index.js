const { V2, PrivateKey, PublicKey, SymmetricKey } = require('../dist');

let symEncoded, pkEncoded, pubEncoded, signedMessage, cryptedMessage;

const generateKeys = async () => {
  const protocol = new V2();
  sym = await protocol.symmetric();
  pk = await protocol.private();
  pub = await pk.public();

  console.log('SYM ----', sym.encode());
  symEncoded = sym.encode();
  console.log('PK  ----', pk.encode());
  pkEncoded = pk.encode();
  console.log('PUB ----', pub.encode());
  pubEncoded = pub.encode();
};

const sign = async () => {
  const protocol = new V2();

  const pk = new PrivateKey(protocol);
  await pk.base64(pkEncoded);

  const signed = await protocol.sign('toddzzszsz', pk, 'blop');
  console.log(signed);
  signedMessage = signed;
};

const verify = async () => {
  const protocol = new V2();

  const pub = new PublicKey(protocol);
  await pub.base64(pubEncoded);

  const verified = await protocol.verify(signedMessage, pub, 'blop');
  console.log(verified);
};

const encrypt = async () => {
  const protocol = new V2();

  const sym = new SymmetricKey(protocol);
  await sym.base64(symEncoded);

  const crypted = await protocol.encrypt('toddz', sym, 'blopblop');
  console.log(crypted);
  cryptedMessage = crypted;
};

const decrypt = async () => {
  const protocol = new V2();

  const sym = new SymmetricKey(protocol);
  await sym.base64(symEncoded);

  const decrypted = await protocol.decrypt(cryptedMessage, sym, 'blopblop');
  console.log(decrypted);
};

generateKeys()
  .then(sign)
  .then(verify)
  .then(encrypt)
  .then(decrypt)
  .catch(console.log);
