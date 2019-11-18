import { crypto_sign_PUBLICKEYBYTES } from 'libsodium-wrappers-sumo';

import { AbstractKey } from './abstract';

import { Protocol } from '../protocol/interface';
import { V2 } from '../protocol/V2';

export class PublicKey extends AbstractKey {
  /***
   * V2
   *
   * syntactic sugar for constructor forcing use of protocol V2
   *
   * @function
   * @api public
   *
   * @returns {PublicKey}
   */
  static V2(): PublicKey {
    return new PublicKey(new V2());
  }

  constructor(protocol: Protocol) {
    super(protocol);
  }

  public async inject(rawKey: Buffer) {
    if (this.protocol instanceof V2) {
      if (!(rawKey instanceof Buffer)) {
        throw new TypeError('Raw key must be provided as a buffer');
      }
      const len = Buffer.byteLength(rawKey);
      await this.ready;
      if (len !== crypto_sign_PUBLICKEYBYTES) {
        throw new Error(`Public keys must be 32 bytes long; ${len} given.`);
      }
    }
    this._keyBuffer = rawKey;
    return;
  }
}

/***
 * PublicKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
export { PublicKeyV2 as V2 };

class PublicKeyV2 extends PublicKey {
  constructor() {
    super(new V2());
  }
}
