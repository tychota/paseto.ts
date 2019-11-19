import { randombytes_buf } from 'libsodium-wrappers-sumo';

import { AbstractKey } from './abstract';

import { Protocol } from '../protocol/interface';
import { V2 } from '../protocol/V2';
import { hkdf } from 'utils';

const INFO_ENCRYPTION = 'paseto-encryption-key';
const INFO_AUTHENTICATION = 'paseto-auth-key-for-aead';

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
    this._key = rawKey;
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

  public async split(salt: Buffer) {
    const hkdfFn = hkdf('sha384');

    const encryptionKey = await hkdfFn(this._key as Buffer, salt, 32, INFO_ENCRYPTION);
    const authenticationKey = await hkdfFn(this._key as Buffer, salt, 32, INFO_AUTHENTICATION);

    return [encryptionKey, authenticationKey];
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
