export class PasetoError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'PasetoError';
    Error.captureStackTrace(this, this.constructor);
  }
}
