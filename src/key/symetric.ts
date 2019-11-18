import { randombytes_buf } from 'libsodium-wrappers-sumo';

import { AbstractKey } from './abstract';

import { Protocol } from '../protocol/interface';
import { V2 } from '../protocol/V2';

export class SymmetricKey extends AbstractKey {
  /***
   * V2
   *
   * syntactic sugar for constructor forcing use of protocol V2
   *
   * @function
   * @api public
   *
   * @returns {SymmetricKey}
   */
  static V2(): SymmetricKey {
    return new SymmetricKey(new V2());
  }

  constructor(protocol: Protocol) {
    super(protocol);
  }

  public async inject(rawKey: Buffer) {
    await this.ready;
    if (!(rawKey instanceof Buffer)) {
      throw new TypeError('Raw key must be provided as a buffer');
    }
    this._keyBuffer = rawKey;
    return;
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
  public async generate(): Promise<SymmetricKey> {
    await this.ready;
    await this.inject(Buffer.from(randombytes_buf(this.protocol.symmetricKeyLength)));
    return this;
  }
}

/***
 * SymmetricKeyV2
 *
 * subclass forcing use of V2
 *
 * @constructor
 * @api public
 */
export { SymmetricKeyV2 as V2 };

class SymmetricKeyV2 extends SymmetricKey {
  constructor() {
    super(new V2());
  }
}
