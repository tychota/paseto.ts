import { V2, SymmetricKey, PrivateKey, PublicKey } from '../src';

import { randombytes_buf, crypto_sign_keypair } from 'libsodium-wrappers-sumo';

describe('Protocol V2', () => {
  const v2 = new V2();

  describe('keygen', () => {
    it('should generate a symmetric key', async () => {
      // when
      const symmetricKey = await v2.symmetric();

      // then
      expect(symmetricKey).toBeInstanceOf(SymmetricKey);
      expect(v2.symmetricKeyLength).toEqual(Buffer.byteLength(symmetricKey.raw));
    });

    it('should generate a private key', async () => {
      // when
      const privateKey = await v2.private();

      // then
      expect(privateKey).toBeInstanceOf(PrivateKey);
      expect(64).toEqual(Buffer.byteLength(privateKey.raw));
    });
  });

  describe('authenticated encryption', () => {
    let key: SymmetricKey, message: string | Buffer, footer: string | Buffer;

    beforeEach(async () => {
      footer = 'footer';

      const rawKey = Buffer.from(randombytes_buf(32));

      key = SymmetricKey.V2();
      await key.inject(rawKey);
    });

    describe('text', () => {
      beforeEach(() => {
        message = 'test';
      });

      it('should encrypt and decrypt successfully', async () => {
        // when
        const token = await v2.encrypt(message, key, '');
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v2.local.');

        // when
        const data = await v2.decrypt(token, key, '');
        // then
        expect(typeof data).toBe('string');
        expect(data).toEqual(message);
      });

      it('should encrypt and decrypt successfully with footer', async () => {
        // when
        const token = await v2.encrypt(message, key, footer);
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v2.local.');

        // when
        const data = await v2.decrypt(token, key, footer);
        // then
        expect(typeof data).toBe('string');
        expect(data).toEqual(message);
      });
    });

    describe('json (stringified)', () => {
      beforeEach(() => {
        const year = new Date().getUTCFullYear() + 1;
        message = JSON.stringify({ data: 'this is a signed message', expires: year + '-01-01T00:00:00+00:00' });
      });

      it('should encrypt and decrypt successfully', async () => {
        // when
        const token = await v2.encrypt(message, key, '');
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v2.local.');

        // when
        const data = await v2.decrypt(token, key, '');
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should encrypt and decrypt successfully with footer', async () => {
        // when
        const token = await v2.encrypt(message, key, footer);
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 9)).toBe('v2.local.');

        // when
        const data = await v2.decrypt(token, key, footer);
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });
    });

    // describe('errors', () => {
    //   const InvalidVersionError = require('../lib/error/InvalidVersionError');

    //   const v1 = new V1();

    //   it('should error on encryption with an invalid key version', async () => {
    //     V1.encrypt('test', key, '')
    //       .then(token => {
    //         expect(false).toBeTruthy(); // fail if we go through here
    //       })
    //       .catch(err => {
    //         expect(err).toBeTruthy();

    //         expect(err instanceof InvalidVersionError).toBeTruthy();
    //         expect(err.message).toBe('The given key is not intended for this version of PASETO.');

    //         done();
    //       });
    //   });

    //   it('should error on decryption with an invalid key version', async () => {
    //     v2.encrypt('test', key, '')
    //       .then(token => {
    //         expect(token).toBeTruthy();

    //         // nest so that we catch the right error
    //         return V1.decrypt(token, key, '')
    //           .then(token => {
    //             expect(false).toBeTruthy(); // fail if we go through here
    //           })
    //           .catch(err => {
    //             expect(err).toBeTruthy();

    //             expect(err instanceof InvalidVersionError).toBeTruthy();
    //             expect(err.message).toBe('The given key is not intended for this version of PASETO.');

    //             done();
    //           });
    //       })
    //       .catch(err => {
    //         return done(err);
    //       });
    //   });
    // });
  });

  describe('signing', () => {
    let secretKey: PrivateKey, publicKey: PublicKey, message: string | Buffer, footer: string | Buffer;

    beforeEach(async () => {
      footer = 'footer';

      const keypair = crypto_sign_keypair();

      secretKey = PrivateKey.V2();
      // @ts-ignore
      secretKey.inject(Buffer.from(keypair.privateKey, 'binary'));

      publicKey = PublicKey.V2();
      // @ts-ignore
      publicKey.inject(Buffer.from(keypair.publicKey, 'binary'));
    });

    describe('text', () => {
      beforeEach(() => {
        message = 'test';
      });

      it('should sign and verify successfully', async () => {
        // when
        const token = await v2.sign(message, secretKey, '');
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v2.public.');

        // when
        const data = await v2.verify(token, publicKey, '');
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should sign and verify successfully with footer', async () => {
        // when
        const token = await v2.sign(message, secretKey, footer);
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v2.public.');

        // when
        const data = await v2.verify(token, publicKey, footer);
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
        const token = await v2.sign(message, secretKey, '');
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v2.public.');

        // when
        const data = await v2.verify(token, publicKey, '');
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });

      it('should sign and verify successfully with footer', async () => {
        // when
        const token = await v2.sign(message, secretKey, footer);
        // then
        expect(typeof token).toBe('string');
        expect(token.substring(0, 10)).toBe('v2.public.');

        // when
        const data = await v2.verify(token, publicKey, footer);
        // then
        expect(typeof data).toBe('string');
        expect(data).toBe(message);
      });
    });

    // describe('errors', () => {
    //   const InvalidVersionError = require('../lib/error/InvalidVersionError');

    //   const V1 = new Paseto.V1();

    //   it('should error on signing with an invalid key version - callback api', async () => {
    //     V1.sign('test', secretKey, '', function(err, token) {
    //       expect(err).toBeTruthy();
    //       expect(!token).toBeTruthy();

    //       expect(err instanceof InvalidVersionError).toBeTruthy();
    //       expect(err.message).toBe('The given key is not intended for this version of PASETO.');

    //       done();
    //     });
    //   });

    //   it('should error on signing with an invalid key version', async () => {
    //     V1.sign('test', secretKey, '')
    //       .then(token => {
    //         expect(false).toBeTruthy(); // fail if we go through here
    //       })
    //       .catch(err => {
    //         expect(err).toBeTruthy();

    //         expect(err instanceof InvalidVersionError).toBeTruthy();
    //         expect(err.message).toBe('The given key is not intended for this version of PASETO.');

    //         done();
    //       });
    //   });

    //   it('should error on verifing with an invalid key version', async () => {
    //     v2.sign('test', secretKey, '')
    //       .then(token => {
    //         expect(token).toBeTruthy();

    //         // nest so that we catch the right error
    //         return V1.verify(token, publicKey, '')
    //           .then(token => {
    //             expect(false).toBeTruthy(); // fail if we go through here
    //           })
    //           .catch(err => {
    //             expect(err).toBeTruthy();

    //             expect(err instanceof InvalidVersionError).toBeTruthy();
    //             expect(err.message).toBe('The given key is not intended for this version of PASETO.');

    //             done();
    //           });
    //       })
    //       .catch(err => {
    //         return done(err);
    //       });
    //   });
    // });
  });
});
