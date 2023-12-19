import * as functions from "firebase-functions";
import crypto from "crypto";
import {ethers} from "ethers";

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
};

export const sha256 = (data: string | Buffer): Buffer => {
  return crypto.createHash("sha256").update(data).digest();
};

export const INVALID_USER_NAME_TOO_SHORT =
  "invalid username: must be at least 5 characters";
export const INVALID_USER_NAME_EMTPY_LABEL =
  "invalid username: empty label";
export const INVALID_USER_NAME_DISALLOWED_CHARACTERS =
  "invalid username: disallowed characters";
export const INVALID_USER_NAME_NON_MIZU_NAME =
  "invalid username: must end with mizu";

export const genNameHash = (username: string) => {
  username = username.trim().toLowerCase();
  validateUsername(username);
  return nameHash(username).slice(2); // remove 0x
};

// the name is with .mizu suffix
const validateUsername = (username: string) => {
  if (username.length < 10) {
    throw new HexlinkError(400, INVALID_USER_NAME_TOO_SHORT);
  }
  const labels = username.split(".");
  if (labels[labels.length - 1] != "mizu") {
    throw new HexlinkError(400, INVALID_USER_NAME_NON_MIZU_NAME);
  }
  for (const label of labels) {
    if (label.length == 0) {
      throw new HexlinkError(400, INVALID_USER_NAME_EMTPY_LABEL);
    }
    if (!/^[a-z0-9]+$/.test(label)) {
      throw new HexlinkError(400, INVALID_USER_NAME_DISALLOWED_CHARACTERS);
    }
  }
  return username;
};

const nameHash = (name: string): string => {
  if (name == "") {
    return ethers.ZeroHash;
  }
  const index = name.indexOf(".");
  if (index === -1) {
    return ethers.solidityPackedKeccak256(
        ["bytes32", "bytes32"],
        [nameHash(""), ethers.keccak256(ethers.toUtf8Bytes(name))]
    );
  } else {
    const label = name.slice(0, index);
    const remainder = name.slice(index + 1);
    return ethers.solidityPackedKeccak256(
        ["bytes32", "bytes32"],
        [nameHash(remainder), ethers.keccak256(ethers.toUtf8Bytes(label))]
    );
  }
};

export const toBuffer = (data: string): Buffer => {
  data = data.startsWith("0x") ? data.slice(2) : data;
  return Buffer.from(data, "hex");
};
