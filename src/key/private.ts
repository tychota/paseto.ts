import {
  crypto_sign_SECRETKEYBYTES,
  crypto_sign_PUBLICKEYBYTES,
  crypto_sign_SEEDBYTES,
  crypto_sign_seed_keypair,
  crypto_sign_ed25519_sk_to_pk,
  crypto_sign_keypair,
} from 'libsodium-wrappers-sumo';

import { AbstractKey } from './abstract';
import { PublicKey } from './public';

import * as extcrypto from '../extcrypto';

import { Protocol } from '../protocol/interface';
import { V2 } from '../protocol/V2';
import { V1 } from '../protocol/V1';

/***
 * PrivateKey
 *
 * private key for asymmetric cryptography
 *
 * @constructor
 *
 * @api public
 *
 * @param {Object} protocol
 */
export class PrivateKey extends AbstractKey {
  /***
   * V2
   *
   * syntactic sugar for constructor forcing use of protocol V2
   *
   * @function
   * @api public
   *
   * @returns {PrivateKey}
   */
  static V2(): PrivateKey {
    return new PrivateKey(new V2());
  }

  constructor(protocol: Protocol) {
    super(protocol);
  }

  /***
   * inject
   *
   * complete construction asynchronously
   *
   * @function
   *
   * @api public
   *
   * @param {String|Buffer} rawKey
   * @returns {Callback|Promise}
   */
  public async inject(rawKey: Buffer | string): Promise<void> {
    if (this.protocol instanceof V2) {
      await this.ready;
      this.injectV2(rawKey as Buffer);
      return;
    }
    if (this.protocol instanceof V1) {
      this.injectV1(rawKey as string);
      return;
    }
    throw new Error('Unimplemented');
  }
  private injectV1(rawKey: string) {
    this._key = rawKey;
  }

  private injectV2(rawKey: Buffer) {
    if (!(rawKey instanceof Buffer)) {
      throw new TypeError('Raw key must be provided as a buffer');
    }

    const keyLength = Buffer.byteLength(rawKey);
    const expectedKeyLength = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;

    if (keyLength === expectedKeyLength) {
      this._key = rawKey.slice(0, crypto_sign_SECRETKEYBYTES);
      return;
    } else if (keyLength !== crypto_sign_SECRETKEYBYTES) {
      if (keyLength !== crypto_sign_SEEDBYTES) {
        throw new Error(`Secret keys must be 32 or 64 bytes long; ${keyLength} given.`);
      }

      this._key = Buffer.from(crypto_sign_seed_keypair(rawKey).privateKey);
      return;
    }

    this._key = rawKey;
  }

  /***
   * generate
   *
   * complete construction asynchronously, generating key
   *
   * @function
   * @api public
   *
   * @returns {Promise}
   */
  public async generate(): Promise<PrivateKey> {
    if (this.protocol instanceof V2) {
      await this.ready;
      await this.inject(Buffer.from(crypto_sign_keypair().privateKey));
      return this;
    }
    if (this.protocol instanceof V2) {
      await this.ready;
      await this.inject(extcrypto.keygen());
      return this;
    }
    throw new Error('Unimplemented');
  }

  /***
   * public
   *
   * return the corresponding public key object
   *
   * @function
   * @api public
   *
   * @returns {Promise}
   */
  async public(): Promise<PublicKey> {
    const pk = new PublicKey(this.protocol);
    if (this.protocol instanceof V2) {
      await this.ready;
      const rawKey = Buffer.from(crypto_sign_ed25519_sk_to_pk(this.raw as Buffer));
      pk.inject(rawKey);
      return pk;
    }
    throw new Error('Unimplemented');
  }
}

/***
 * PrivateKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
export { PrivateKeyV2 as V2 };

class PrivateKeyV2 extends PrivateKey {
  constructor() {
    super(new V2());
  }
}
