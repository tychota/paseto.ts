export class SecurityError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'SecurityError';
    Error.captureStackTrace(this, this.constructor);
  }
}
