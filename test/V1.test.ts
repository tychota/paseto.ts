import sodium from 'libsodium-wrappers-sumo';

import { V1Deprecated, V2, SymmetricKey, PrivateKey, PublicKey } from '../src/';
import { extractRsaPublicKey, generateRsaPrivateKey } from '../native_modules/rsa_keygen_addon';

describe('Protocol v1', () => {
  const v1 = new V1Deprecated();

  describe('keygen', () => {
    it('should generate a symmetric key', async () => {
      // when
      const symmetricKey = await v1.symmetric();

      // then
      expect(symmetricKey instanceof SymmetricKey).toBeTruthy();
      expect(v1.symmetricKeyLength).toBe(Buffer.byteLength(symmetricKey.raw));
    });

    it('should generate a private key', async () => {
      // when
      const privateKey = await v1.private();

      // then
      expect(privateKey instanceof PrivateKey).toBeTruthy();
      expect('-----BEGIN RSA PRIVATE KEY-----').toBe(privateKey.raw.slice(0, 31));
    });
  });

  describe('authenticated encryption', () => {
    let key: SymmetricKey, message: string | Buffer, footer: string | Buffer;

    beforeEach(async () => {
      footer = 'footer';

      const rawKey = Buffer.from(sodium.randombytes_buf(32));

      key = SymmetricKey.V1Deprecated();
      await key.inject(rawKey);
    });

    describe('text', () => {
      beforeEach(() => {
        message = 'test';
      });

      it('should encrypt and decrypt successfully', async () => {
        // when
        const token = await v1.encrypt(message, key, '');

        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v1.local.');

        // when
        const data = await v1.decrypt(token, key, '');

        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should encrypt and decrypt successfully with footer', async () => {
        // when
        const token = await v1.encrypt(message, key, footer);

        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v1.local.');

        // when
        const data = await v1.decrypt(token, key, footer);

        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });
    });

    describe('json (stringified)', () => {
      beforeEach(() => {
        const year = new Date().getUTCFullYear() + 1;
        message = JSON.stringify({ data: 'this is a signed message', expires: year + '-01-01T00:00:00+00:00' });
      });

      it('should encrypt and decrypt successfully', async () => {
        // when
        const token = await v1.encrypt(message, key, '');

        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v1.local.');

        // when
        const data = await v1.decrypt(token, key, '');

        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should encrypt and decrypt successfully with footer', async () => {
        // when
        const token = await v1.encrypt(message, key, footer);

        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v1.local.');

        // when
        const data = await v1.decrypt(token, key, footer);

        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });
    });

    describe('errors', () => {
      const v2 = new V2();

      it('should error on encryption with an invalid key version', async () => {
        // guard
        expect.assertions(2);

        try {
          // when
          await v2.encrypt('test', key, '');
        } catch (err) {
          // then
          expect(err.name).toBe('InvalidVersionError');
          expect(err.message).toBe('The given key is not intended for this version of PASETO.');
        }
      });

      it('should error on decryption with an invalid key version', async () => {
        // guard
        expect.assertions(3);

        // when
        const token = await v1.encrypt('test', key, '');
        // then
        expect(token).toBeTruthy();

        try {
          // when
          await v2.decrypt(token, key, '');
        } catch (err) {
          // then
          expect(err.name).toBe('InvalidVersionError');
          expect(err.message).toBe('The given key is not intended for this version of PASETO.');
        }
      });
    });
  });

  describe('signing', () => {
    let secretKey: PrivateKey, publicKey: PublicKey, message: string | Buffer, footer: string | Buffer;

    beforeEach(async () => {
      footer = 'footer';

      const rawSecretKey = await generateRsaPrivateKey();
      const rawPublicKey = await extractRsaPublicKey(rawSecretKey);

      secretKey = PrivateKey.V1Deprecated();
      await secretKey.inject(rawSecretKey);

      publicKey = PublicKey.V1Deprecated();
      await publicKey.inject(rawPublicKey);
    });

    describe('text', () => {
      beforeEach(() => {
        message = 'test';
      });

      it('should sign and verify successfully', async () => {
        // when
        const token = await v1.sign(message, secretKey, '');
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v1.public.');

        // when
        const data = await v1.verify(token, publicKey, '');
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should sign and verify successfully with footer', async () => {
        // when
        const token = await v1.sign(message, secretKey, footer);
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v1.public.');

        // when
        const data = await v1.verify(token, publicKey, footer);
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });
    });

    describe('json (stringified)', () => {
      beforeEach(() => {
        const year = new Date().getUTCFullYear() + 1;
        message = JSON.stringify({ data: 'this is a signed message', expires: year + '-01-01T00:00:00+00:00' });
      });

      it('should sign and verify successfully', async () => {
        // when
        const token = await v1.sign(message, secretKey, '');
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v1.public.');

        // when
        const data = await v1.verify(token, publicKey, '');
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should sign and verify successfully with footer', async () => {
        // when
        const token = await v1.sign(message, secretKey, footer);
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v1.public.');

        // when
        const data = await v1.verify(token, publicKey, footer);
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });
    });

    describe('errors', () => {
      const v2 = new V2();

      it('should error on signing with an invalid key version', async () => {
        // guard
        expect.assertions(2);

        try {
          //when
          await v2.sign('test', secretKey, '');
        } catch (err) {
          //then
          expect(err.name).toBe('InvalidVersionError');
          expect(err.message).toBe('The given key is not intended for this version of PASETO.');
        }
      });

      it('should error on verifing with an invalid key version', async () => {
        // guard
        expect.assertions(3);
        //when
        const token = await v1.sign('test', secretKey, '');
        // then
        expect(token).toBeTruthy();

        try {
          // when
          await v2.verify(token, publicKey, '');
        } catch (err) {
          // then
          expect(err.name).toBe('InvalidVersionError');
          expect(err.message).toBe('The given key is not intended for this version of PASETO.');
        }
      });
    });
  });
});
