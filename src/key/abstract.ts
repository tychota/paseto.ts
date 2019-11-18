import { Protocol } from 'protocol/interface';
import { ready, base64_variants, from_base64, to_base64 } from 'libsodium-wrappers-sumo';

export abstract class AbstractKey {
  protected _keyBuffer!: Buffer;
  constructor(protected readonly _protocol: Protocol) {}

  public get protocol() {
    return this._protocol;
  }
  protected get ready() {
    return ready;
  }

  public abstract async inject(rawKey: Buffer): Promise<void>;

  /***
   * base64
   *
   * complete construction asynchronously using base64 encoded key
   *
   * @function
   *
   * @api public
   *
   * @param {Buffer} serializedKey
   * @returns {Promise}
   */
  public base64(serializedKey: string): Promise<void> {
    if (typeof serializedKey !== 'string') {
      throw new TypeError(`Can only decode string. Given ${serializedKey} of type ${typeof serializedKey}`);
    }
    const rawKey = Buffer.from(from_base64(serializedKey, base64_variants.URLSAFE_NO_PADDING));
    return this.inject(rawKey);
  }

  /***
   * hex
   *
   * complete construction asynchronously using hex encoded key
   *
   * @function
   *
   * @api public
   *
   * @param {Buffer} serializedKey
   * @returns {Promise}
   */
  public hex(serializedKey: string): Promise<void> {
    if (typeof serializedKey !== 'string') {
      throw new TypeError(`Can only decode string. Given ${serializedKey} of type ${typeof serializedKey}`);
    }
    return this.inject(Buffer.from(serializedKey, 'hex'));
  }

  /***
   * encode
   *
   * encode the raw key as b64url
   *
   * @function
   * @api public
   *
   * @returns {String}
   */
  public encode(): string {
    if (!(this._keyBuffer instanceof Buffer)) {
      throw new TypeError('Can only encode buffer');
    }
    return to_base64(this._keyBuffer, base64_variants.URLSAFE_NO_PADDING);
  }

  /***
   * raw
   *
   * return the raw key buffer
   *
   * @function
   * @api public
   *
   * @returns {Buffer}
   */
  public get raw(): Buffer {
    return this._keyBuffer;
  }
}
