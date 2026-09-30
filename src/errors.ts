export class CryptoError extends Error {
  constructor(
    message: string,
    readonly code:
      | "DECRYPT_FAILED"
      | "INVALID_FORMAT"
      | "INVALID_KEY"
      | "UNSAFE_KDF_PARAMS"
      | "UNSUPPORTED",
  ) {
    super(message);
    this.name = "CryptoError";
  }
}
