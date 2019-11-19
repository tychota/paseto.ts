//@ts-ignore
import rsaKeygen from '../../build/Release/rsa_keygen_addon';

export const generateRsaPrivateKey: () => string = rsaKeygen.generateRsaPrivateKey;
export const extractRsaPublicKey: (privateKey: string) => string = rsaKeygen.extractRsaPublicKey;
