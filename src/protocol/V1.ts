import crypto from 'crypto';
import { Protocol } from './interface';

import { PrivateKey } from '../key/private';
import { SymmetricKey } from '../key/symetric';

import { InvalidVersionError } from '../error/InvalidVersionError';
import { PasetoError } from '../error/PasetoError';

import { parse, encodeAdditionalData, toBase64URLSafe } from '../utils';

const SYMMETRIC_KEY_BYTES = 32;
const CIPHER_MODE = 'aes-256-ctr';
const HASH_ALGO = 'sha384';
const NONCE_SIZE = 32;
const MAC_SIZE = 48;
const SIGN_SIZE = 256;

/***
 * V1
 *
 * protocol version 1
 *
 * @deprecated
 *
 * @constructor
 * @api public
 */
export class V1 implements Protocol {
  private _repr: string;
  public constructor() {
    this._repr = 'v1';
  }

  /***
   * sklength
   *
   * get symmetric key length
   *
   * @function
   * @api public
   *
   * @returns {Number}
   */
  get symmetricKeyLength(): number {
    return SYMMETRIC_KEY_BYTES;
  }

  private get headerLocal() {
    return Buffer.from(`${this._repr}.local.`, 'utf-8');
  }
  private get headerPublic() {
    return Buffer.from(`${this._repr}.public.`, 'utf-8');
  }

  /***
   * private
   *
   * generate a private key for use with the protocol
   *
   * @function
   * @api public
   *
   * @returns {Promise}
   */
  public private(): Promise<PrivateKey> {
    const privateKey = new PrivateKey(new V1());
    return privateKey.generate();
  }

  /***
   * symmetric
   *
   * generate a symmetric key for use with the protocol
   *
   * @function
   * @api public
   *
   * @param {Function} cb
   * @returns {Callback|Promise}
   */
  public symmetric(): Promise<SymmetricKey> {
    const symmetricKey = new SymmetricKey(new V1());
    return symmetricKey.generate();
  }

  private nonce(message: Buffer, nonceKey: Buffer) {
    return crypto
      .createHmac(HASH_ALGO, nonceKey)
      .update(message)
      .digest()
      .slice(0, 32);
  }

  /***
   * encrypt
   *
   * symmetric authenticated encryption
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} data
   * @param {Object} key
   * @param {String|Buffer} footer
   * @returns {Promise}
   */
  public async encrypt(data: string | Buffer, key: SymmetricKey, footer: string | Buffer = ''): Promise<string> {
    if (!(key.protocol instanceof V1)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }

    const nonce = '';
    const [parsedData, parsedFooter, parsedNonce] = parse('utf-8')(data, footer, nonce);

    return this.aeadEncrypt(key, this.headerLocal, parsedData, parsedFooter, parsedNonce);
  }

  private async aeadEncrypt(key: SymmetricKey, header: Buffer, plaintext: Buffer, footer: Buffer, nonceKey: Buffer) {
    const nonce = !!nonceKey ? this.nonce(plaintext, nonceKey) : this.nonce(plaintext, crypto.randomBytes(NONCE_SIZE));

    const [enckey, authkey] = await key.split(nonce.slice(0, 16));

    const encryptor = crypto.createCipheriv(CIPHER_MODE, enckey, nonce.slice(16, 32));
    const ciphertext = Buffer.concat([encryptor.update(plaintext), encryptor.final()]);

    if (!ciphertext) {
      throw new PasetoError('Encryption failed.');
    }

    const payload = encodeAdditionalData(header, nonce, ciphertext, footer);

    const authenticator = crypto.createHmac(HASH_ALGO, authkey);
    const mac = authenticator.update(payload).digest();

    const token = `${header.toString('utf-8')}${toBase64URLSafe(Buffer.concat([nonce, ciphertext, mac]))}`;

    return Buffer.byteLength(footer) === 0 ? token : `${token}.${toBase64URLSafe(footer)}`;
  }
}
