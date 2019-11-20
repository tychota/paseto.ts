//@ts-ignore
import rsaKeygen from '../../build/Release/rsa_keygen_addon';

export const generateRsaPrivateKey: () => Promise<string> = rsaKeygen.generateRsaPrivateKey;
export const extractRsaPublicKey: (privateKey: string) => Promise<string> = rsaKeygen.extractRsaPublicKey;
