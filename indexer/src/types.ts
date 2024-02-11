export type HexString = `0x${string}`;

export interface Passkey {
  id: string;
  pub_key: {
    x: Uint8Array;
    y: Uint8Array;
  }
}

export class ServerError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}