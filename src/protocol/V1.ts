import crypto from 'crypto';
import { Protocol } from './interface';

import { PrivateKey } from '../key/private';
import { SymmetricKey } from '../key/symetric';

import { InvalidVersionError } from '../error/InvalidVersionError';
import { PasetoError } from '../error/PasetoError';
import { SecurityError } from '../error/SecurityError';

import { parse, encodeAdditionalData, toBase64URLSafe, constantTimeCompare } from '../utils';
import { decapsulate } from '../decapsulate';
import { PublicKey } from 'key/public';

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
   * encrypt
   *
   * symmetric authenticated encryption (private api)
   *
   * @function
   * @api private
   *
   * @param {String|Buffer} data
   * @param {Object} key
   * @param {String|Buffer} footer
   * @returns {Promise}
   */
  private async encryptWithNonce(data: string | Buffer, key: SymmetricKey, footer: string | Buffer = '', nonce: string): Promise<string> {
    if (!(key.protocol instanceof V1)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }
    const [parsedData, parsedFooter, parsedNonce] = parse('utf-8')(data, footer, nonce);

    return this.aeadEncrypt(key, this.headerLocal, parsedData, parsedFooter, parsedNonce);
  }

  private async aeadEncrypt(key: SymmetricKey, header: Buffer, plaintext: Buffer, footer: Buffer, nonceKey: Buffer) {
    const nonce = !!nonceKey ? this.nonce(plaintext, nonceKey) : this.nonce(plaintext, crypto.randomBytes(NONCE_SIZE));

    const [encryptionKey, authenticationKey] = await key.split(nonce.slice(0, 16));

    const encryptor = crypto.createCipheriv(CIPHER_MODE, encryptionKey, nonce.slice(16, 32));
    const ciphertext = Buffer.concat([encryptor.update(plaintext), encryptor.final()]);

    if (!ciphertext) {
      throw new PasetoError('Encryption failed.');
    }

    const payload = encodeAdditionalData(header, nonce, ciphertext, footer);

    const authenticator = crypto.createHmac(HASH_ALGO, authenticationKey);
    const mac = authenticator.update(payload).digest();

    const token = `${header.toString('utf-8')}${toBase64URLSafe(Buffer.concat([nonce, ciphertext, mac]))}`;

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
   * @returns {Promise}
   */
  public decrypt(token: string, key: SymmetricKey, footer: any): Promise<string> {
    if (!(key.protocol instanceof V1)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }

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
  private async aeadDecrypt(key: SymmetricKey, header: Buffer, payload: Buffer, footer: Buffer): Promise<string> {
    // recover nonce
    const payloadLength = Buffer.byteLength(payload);
    const nonceLength = NONCE_SIZE;
    const nonce = Buffer.from(payload).slice(0, nonceLength);

    // decrypt and verify
    const ciphertext = Buffer.from(payload).slice(nonceLength, payloadLength - MAC_SIZE);
    const mac = Buffer.from(payload).slice(payloadLength - MAC_SIZE);

    const [encryptionKey, authenticationKey] = await key.split(nonce.slice(0, 16));
    payload = encodeAdditionalData(header, nonce, ciphertext, footer);

    const authenticator = crypto.createHmac(HASH_ALGO, authenticationKey);
    const calc = authenticator.update(payload).digest();

    if (!constantTimeCompare(mac, calc)) {
      throw new SecurityError('Invalid MAC for given ciphertext.');
    }

    const decryptor = crypto.createDecipheriv(CIPHER_MODE, encryptionKey, nonce.slice(16, 32));
    const plaintext = Buffer.concat([decryptor.update(ciphertext), decryptor.final()]);

    // an empty buffer is truthy, if no ciphertext
    if (!plaintext) {
      throw new PasetoError('Decryption failed.');
    }

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
  public async sign(data: string | Buffer, key: PrivateKey, footer: string | Buffer = ''): Promise<string> {
    if (!(key.protocol instanceof V1)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }

    const [parsedData, parsedFooter] = parse('utf-8')(data, footer);

    // sign
    const payload = encodeAdditionalData(this.headerPublic, parsedData, parsedFooter);

    const signer = crypto.createSign('SHA384');
    signer.update(payload);
    signer.end();

    const signature = signer.sign({ key: key.raw, padding: crypto.constants.RSA_PKCS1_PSS_PADDING });

    // format
    const token = `${this.headerPublic.toString('utf-8')}${toBase64URLSafe(Buffer.concat([parsedData, signature]))}`;

    return Buffer.byteLength(footer) === 0 ? token : `${token}.${toBase64URLSafe(parsedFooter)}`;
  }

  /***
   * verify
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
    if (!(key.protocol instanceof V1)) {
      throw new InvalidVersionError('The given key is not intended for this version of PASETO.');
    }

    const [parsedHeader, parsedPayload, parsedFooter] = decapsulate(this.headerPublic, token, footer);

    // recover data
    const payloadLength = Buffer.byteLength(parsedPayload);
    const data = Buffer.from(parsedPayload).slice(0, payloadLength - SIGN_SIZE);
    const signature = Buffer.from(parsedPayload).slice(payloadLength - SIGN_SIZE);

    // verify signature
    const expected = encodeAdditionalData(parsedHeader, data, parsedFooter);

    const verifier = crypto.createVerify('SHA384');
    verifier.update(expected);
    verifier.end();

    const valid = verifier.verify({ key: key.raw, padding: crypto.constants.RSA_PKCS1_PSS_PADDING }, signature);
    if (!valid) {
      throw new PasetoError('Invalid signature for this message');
    }

    // format
    return data.toString('utf-8');
  }
}
