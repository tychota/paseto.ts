import { fromBase64URLSafe, constantTimeCompare, parse } from './utils';

/***
 * hvalidate
 *
 * validate (and remove) header
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @param {Buffer} header
 * @returns {String} token
 */
function validateHeader(token: string, header: Buffer): string {
  const parsed = Buffer.from(token, 'utf-8');

  const headerLength = Buffer.byteLength(header);
  const leading = parsed.slice(0, headerLength);

  if (!constantTimeCompare(header, leading)) {
    throw new Error('Invalid message header');
  }

  return parsed.slice(headerLength).toString('utf-8');
}

/***
 * extract
 *
 * extract footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @returns {Buffer} footer
 */
function extractFooter(token: string): Buffer {
  const pieces = token.split('.');

  return pieces.length > 3 ? fromBase64URLSafe(pieces.pop() as string) : Buffer.from('');
}

/***
 * remove
 *
 * remove footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @returns {String} token
 */
function removeFooter(token: string): string {
  const pieces = token.split('.');

  return pieces.length > 3 ? pieces.slice(0, 3).join('.') : token;
}

/***
 * fvalidate
 *
 * validate (and remove) footer
 *
 * @function
 * @api private
 *
 * @param {String} token
 * @param {Buffer} footer
 * @returns {String} token
 */
function validateFooter(token: string, footer: Buffer): string {
  if (!footer) {
    return token;
  }
  footer = Buffer.concat([Buffer.from('.', 'utf-8'), footer]);

  const trailing = Buffer.concat([Buffer.from('.', 'utf-8'), extractFooter(token)]);

  if (!constantTimeCompare(footer, trailing)) {
    throw new Error('Invalid message footer');
  }

  return removeFooter(token);
}

/***
 * decapsulate
 *
 * validate and remove headers and footers
 *
 * @param {Buffer} header
 * @param {String} token
 * @param {String|Buffer} footer
 * @returns {Array} parsed
 */
export function decapsulate(header: Buffer, token: string, footer: string | Buffer): Array<any> {
  let parsedFooter;
  let parsedToken;
  if (!footer) {
    parsedFooter = extractFooter(token);
    parsedToken = removeFooter(token);
  } else {
    [parsedFooter] = parse('utf-8')(footer);
    parsedToken = validateFooter(token, parsedFooter);
  }

  let payload = validateHeader(parsedToken, header);
  const [parsedPayload] = parse('base64')(payload);

  return [header, parsedPayload, parsedFooter];
}
