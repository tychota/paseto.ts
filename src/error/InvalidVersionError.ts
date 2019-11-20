import { PasetoError } from './PasetoError';

export class InvalidVersionError extends PasetoError {
  public constructor(message: string) {
    super(message);
    this.name = 'InvalidVersionError';
    Error.captureStackTrace(this, this.constructor);
  }
}
