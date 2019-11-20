import { PasetoError } from './PasetoError';

export class EncodingError extends PasetoError {
  public constructor(message: string) {
    super(message);
    this.name = 'EncodingError';
    Error.captureStackTrace(this, this.constructor);
  }
}
