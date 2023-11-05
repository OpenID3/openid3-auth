import * as functions from "firebase-functions";
import crypto from "crypto";

export const epoch = () => {
  return Math.floor(new Date().getTime() / 1000);
};

export class HexlinkError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export const handleError = function(
    res: functions.Response,
    err: unknown
) {
  if (err instanceof HexlinkError) {
    res.status(err.code).json({message: err.message});
  } else {
    console.log("Error: ", err);
    res.status(500).json({message: "internal server error"});
  }
};

export const sha3 = (data: string | Buffer) : Buffer => {
  return crypto.createHash("sha3-256").update(data).digest();
}
