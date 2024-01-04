import { BigNumberish } from "ethers";

export type HexString = `0x${string}`;

export interface LogResponse {
  address: HexString;
  topics: HexString[];
  data: HexString;
  blockNumber: BigNumberish;
  logIndex: BigNumberish;
  transactionHash: string;
  transactionIndex: BigNumberish;
  timeStamp: BigNumberish;
}

export class HexlinkError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export interface Passkey {
  id: string;
  x: HexString;
  y: HexString;
}