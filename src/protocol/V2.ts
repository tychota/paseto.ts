import {
  crypto_generichash,
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
  crypto_aead_xchacha20poly1305_ietf_encrypt,
  crypto_aead_xchacha20poly1305_ietf_decrypt,
  crypto_sign_BYTES,
  crypto_sign_detached,
  crypto_sign_verify_detached,
  randombytes_buf,
  ready,
} from 'libsodium-wrappers-sumo';

import { PrivateKey } from '../key/private';
import { SymmetricKey } from '../key/symetric';

import { parse, encodeAdditionalData, toBase64URLSafe } from '../utils';

import { decapsulate } from '../decapsulate';

import { InvalidVersionError } from '../error/InvalidVersionError';
import { PasetoError } from '../error/PasetoError';

import { Protocol } from './interface';
import { PublicKey } from 'key/public';

const SYMMETRIC_KEY_BYTES = 32;

/***
 * V2
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
export class V2 implements Protocol {
  private _repr: string;
  public constructor() {
    this._repr = 'v2';
  }

  protected get ready() {
    return ready;
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
    const privateKey = new PrivateKey(new V2());
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
   * @returns {Promise}
   */
  public symmetric(): Promise<SymmetricKey> {
    const symmetricKey = new SymmetricKey(new V2());
    return symmetricKey.generate();
  }

  private get headerLocal() {
    return Buffer.from(`${this._repr}.local.`, 'utf-8');
  }
  private get headerPublic() {
    return Buffer.from(`${this._repr}.public.`, 'utf-8');
  }

  /***
   * encrypt
   *
   * symmetric authenticated encryption (public api)
   *
   * @function
   * @api public
   *
   * @param {String|Buffer} data
   * @param {Object} key
   * @param {String|Buffer} footer
   * @returns {Promise}
   */
  public async encrypt(data: string | Buffer, key: SymmetricKey, footer: string | Buffer = ''): Promise<string> {
    return this.encryptWithNonce(data, key, footer, '');
  }

  /***
   * encryptWithNonce
   *
   * symmetric authenticated encryption (private api)
   *
   * this private API is used for vector testing
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} data
   * @param {Object} key
   * @param {String|Buffer} footer
   * @param {String|Buffer} nonce
   * @returns {Promise}
   */
  private async encryptWithNonce(data: string | Buffer, key: SymmetricKey, footer: string | Buffer = '', nonce: string): Promise<string> {
    if (!(key.protocol instanceof V2)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }
    await this.ready;

    const [parsedData, parsedFooter, parsedNonce] = parse('utf-8')(data, footer, nonce);
    return this.aeadEncrypt(key, this.headerLocal, parsedData, parsedFooter, parsedNonce);
  }

  /***
   * aeadEncrypt
   *
   * internals of symmetric authenticated encryption
   *
   * @function
   * @api private
   *
   * @param {Object} key
   * @param {Buffer} header
   * @param {Buffer} plaintext
   * @param {Buffer} footer
   * @param {Buffer} nonce
   * @returns {|Promise}
   */
  private aeadEncrypt(key: SymmetricKey, header: Buffer, plaintext: Buffer, footer: Buffer, nonceKey: Buffer): string {
    // build nonce
    const nonceLen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    nonceKey = nonceKey || randombytes_buf(nonceLen);
    const nonce = Buffer.from(crypto_generichash(nonceLen, plaintext, nonceKey));

    // encrypt
    const additionnalData = encodeAdditionalData(header, nonce, footer);
    const ciphertext = Buffer.from(crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, additionnalData, null, nonce, key.raw as Buffer));

    // format
    const payload = Buffer.concat([nonce, ciphertext]);
    const token = header.toString('utf-8') + toBase64URLSafe(payload);

    return Buffer.byteLength(footer) === 0 ? token : `${token}.${toBase64URLSafe(footer)}`;
  }

  /***
   * decrypt
   *
   * symmetric authenticated decryption
   *
   * @function
   * @api public
   *
   * @param {String} token
   * @param {Object} key
   * @param {String|Buffer} footer
   * @returns {Callback|Promise}
   */
  public async decrypt(token: string, key: SymmetricKey, footer: string | Buffer): Promise<string> {
    if (!(key.protocol instanceof V2)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }
    await this.ready;

    const header = this.headerLocal;
    const [parsedHeader, parsedPayload, parsedFooter] = decapsulate(header, token, footer);

    return this.aeadDecrypt(key, parsedHeader, parsedPayload, parsedFooter);
  }

  /***
   * aeadDecrypt
   *
   * internals of symmetric authenticated decryption
   *
   * @function
   * @api private
   *
   * @param {Object} key
   * @param {Buffer} header
   * @param {Buffer} payload
   * @param {Buffer} footer
   * @returns {Promise}
   */
  private aeadDecrypt(key: SymmetricKey, header: Buffer, payload: Buffer, footer: Buffer): string {
    // recover nonce
    const payloadLength = Buffer.byteLength(payload);
    const nonceLength = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    const nonce = Buffer.from(payload).slice(0, nonceLength);

    // decrypt and verify
    const additionnalData = encodeAdditionalData(header, nonce, footer);
    const ciphertext = Buffer.from(payload).slice(nonceLength, payloadLength);
    const plaintext = Buffer.from(crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, additionnalData, nonce, key.raw as Buffer));

    // format
    return plaintext.toString('utf-8');
  }

  /***
   * sign
   *
   * asymmetric authentication
   *
   * @function
   * @api public
   *
   * @param {String|Buffer} data
   * @param {Object} key
   * @param {String|Buffer} footer
   * @returns {Promise}
   */
  public async sign(data: string | Buffer, key: PrivateKey, footer: string | Buffer): Promise<string> {
    footer = footer || '';

    if (!(key.protocol instanceof V2)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }
    await this.ready;

    const [parsedData, parsedFooter] = parse('utf-8')(data, footer);

    // sign
    const payload = encodeAdditionalData(this.headerPublic, parsedData, parsedFooter);
    const signature = Buffer.from(crypto_sign_detached(payload, key.raw as Buffer));

    // format
    const token = `${this.headerPublic.toString('utf-8')}${toBase64URLSafe(Buffer.concat([parsedData, signature]))}`;
    return Buffer.byteLength(parsedFooter) === 0 ? token : `${token}.${toBase64URLSafe(parsedFooter)}`;
  }

  /***
   * sign
   *
   * asymmetric authentication
   *
   * @function
   * @api public
   *
   * @param {String} token
   * @param {Object} key
   * @param {String|Buffer} footer
   * @returns {Promise}
   */
  public async verify(token: string, key: PublicKey, footer: string | Buffer): Promise<string> {
    if (!(key.protocol instanceof V2)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }

    await this.ready;

    const [parsedHeader, parsedPayload, parsedFooter] = decapsulate(this.headerPublic, token, footer);

    // recover data
    const payloadLength = Buffer.byteLength(parsedPayload);
    const data = Buffer.from(parsedPayload).slice(0, payloadLength - crypto_sign_BYTES);
    const signature = Buffer.from(parsedPayload).slice(payloadLength - crypto_sign_BYTES);

    // verify signature
    const expected = encodeAdditionalData(parsedHeader, data, parsedFooter);
    const valid = crypto_sign_verify_detached(signature, expected, key.raw as Buffer);

    if (!valid) {
      throw new PasetoError('Invalid signature for this message');
    }

    // format
    return data.toString('utf-8');
  }
}
