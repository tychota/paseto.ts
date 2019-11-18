import { PasetoError } from './PasetoError';

export class InvalidVersionError extends PasetoError {
  public constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}
