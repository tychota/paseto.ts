import crypto from 'crypto';
import { from_base64, base64_variants, to_base64, compare } from 'libsodium-wrappers-sumo';

import { PasetoError } from './error/PasetoError';
import { EncodingError } from './error/EncodingError';

export function constantTimeCompare(a: Buffer, b: Buffer) {
  if (!(a instanceof Buffer && b instanceof Buffer)) {
    throw new TypeError('Inputs must be buffers');
  }

  if (Buffer.byteLength(a) !== Buffer.byteLength(b)) {
    throw new TypeError('Buffers must have the same length');
  }

  // default to node implementation
  if (crypto.timingSafeEqual) {
    return crypto.timingSafeEqual(a, b);
  }

  // fallback to libsodium
  return compare(a, b) === 0;
}

export function hkdf(alg: string) {
  let olen: crypto.Hmac;
  try {
    olen = crypto.createHmac(alg, '');
  } catch (ex) {
    throw new Error('Unable to configure HKDF.');
  }

  /***
   * `lambda`
   *
   * execute an hkdf
   *
   * @function
   * @api private
   *
   * @param {Buffer} key
   * @param {Buffer} salt
   * @param {Number} len
   * @param {String} use
   * @param {Function} done
   * @returns {Buffer}
   */
  return async (key: Buffer, salt: Buffer, len: number, use: string) => {
    if (!len || len < 0 || len > 255 * ((olen as any) as number)) {
      throw new Error('Bad output length requested of HKDF.');
    }

    // if salt not provided, set it to a string of zeroes.
    if (!salt) {
      salt = Buffer.alloc((olen as any) as number).fill(0);
    }

    const prk = crypto
      .createHmac(alg, salt)
      .update(key)
      .digest();

    if (Buffer.byteLength(prk) < ((olen as any) as number)) {
      throw new Error('An unexpected condition occurred in the HKDF internals');
    }

    const u = Buffer.from(use);

    let t = Buffer.from('');
    let lb = Buffer.from('');
    let i: Buffer, inp;

    for (let bi = 1; Buffer.byteLength(t) < len; ++((i as any) as number)) {
      i = Buffer.from(String.fromCharCode(bi));
      inp = Buffer.concat([lb, u, i]);

      lb = crypto
        .createHmac(alg, prk)
        .update(inp)
        .digest();
      t = Buffer.concat([t, lb]);
    }

    const orm = Buffer.from(t).slice(0, len);
    return orm;
  };
}

export const parse = (format: 'hex' | 'base64' | 'utf-8') => (...args: (string | Buffer)[]) => {
  if (!['hex', 'base64', 'utf-8'].includes(format)) {
    throw new Error('Unknown format');
  }
  const parser =
    format === 'base64'
      ? fromBase64URLSafe
      : (input: string) => {
          return Buffer.from(input, format);
        };
  return args.map(input => {
    if (!input) {
      return Buffer.from('');
    }
    try {
      return input instanceof Buffer ? input : parser(input);
    } catch (ex) {
      throw new PasetoError('Invalid encoding detected');
    }
  });
};

export const encodeAdditionalData = (...args: (string | Buffer)[]) => {
  const additionnalDataPieces = parse('utf-8')(...args);

  const littleEndian64 = (messageSize: number) => {
    if (messageSize > Number.MAX_SAFE_INTEGER) {
      throw new EncodingError('Message too long to encode');
    }
    const up = ~~(messageSize / 0xffffffff);
    const dn = (messageSize % 0xffffffff) - up;
    let resultBuffer = Buffer.alloc(8);
    resultBuffer.writeUInt32LE(up, 4);
    resultBuffer.writeUInt32LE(dn, 0);
    return resultBuffer;
  };

  return additionnalDataPieces.reduce((accumulator, piece) => {
    let len = littleEndian64(Buffer.byteLength(piece));
    return Buffer.concat([accumulator, len, piece]);
  }, littleEndian64(additionnalDataPieces.length));
};

export const toBase64URLSafe = (buffer: Buffer) => {
  if (!(buffer instanceof Buffer)) {
    throw new TypeError('Can only encode buffer');
  }
  return to_base64(buffer, base64_variants.URLSAFE_NO_PADDING);
};

export const fromBase64URLSafe = (str: string) => {
  if (!(typeof str === 'string')) {
    throw new TypeError('Can only decode string');
  }
  return Buffer.from(from_base64(str, base64_variants.URLSAFE_NO_PADDING));
};
