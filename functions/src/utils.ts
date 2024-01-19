import * as functions from "firebase-functions";
import crypto from "crypto";
import { namehash } from "viem";

export const epoch = () => {
  return Math.floor(new Date().getTime() / 1000);
};

export class ServerError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export const handleError = (res: functions.Response, err: unknown) => {
  if (err instanceof ServerError) {
    res.status(err.code).json({ message: err.message });
  } else {
    console.log("Error: ", err);
    res.status(500).json({ message: "internal server error" });
  }
};

export const sha3 = (data: string | Buffer): Buffer => {
  return crypto.createHash("sha3-256").update(data).digest();
};

export const sha256 = (data: string | Buffer): Buffer => {
  return crypto.createHash("sha256").update(data).digest();
};

export const INVALID_USER_NAME_TOO_SHORT =
  "invalid username: must be at least 5 characters";
export const INVALID_USER_NAME_EMTPY_LABEL = "invalid username: empty label";
export const INVALID_USER_NAME_DISALLOWED_CHARACTERS =
  "invalid username: disallowed characters";
export const INVALID_USER_NAME_NON_MIZU_NAME =
  "invalid username: must end with mizu";
export const SUBDOMAIN_NOT_ALLOWED = "invalid username: subdomain not allowed";

export const genNameHash = (username: string) => {
  username = validateUsername(username);
  return namehash(username);
};

// the name is with .mizu suffix
const validateUsername = (username: string) => {
  username = username.trim().toLowerCase();
  if (!username.endsWith(".mizu")) {
    throw new ServerError(400, INVALID_USER_NAME_NON_MIZU_NAME);
  }
  const labels = username.split(".");
  if (labels.length > 2) {
    throw new ServerError(400, SUBDOMAIN_NOT_ALLOWED);
  }
  if (labels[0].length < 5) {
    throw new ServerError(400, INVALID_USER_NAME_TOO_SHORT);
  }
  if (!/^[a-z0-9]+$/.test(labels[0])) {
    throw new ServerError(400, INVALID_USER_NAME_DISALLOWED_CHARACTERS);
  }
  return username;
};

export const toBuffer = (data: string): Buffer => {
  const normalized = data.startsWith("0x") ? data.slice(2) : data;
  return Buffer.from(normalized, "hex");
};

export const formatHex = (data: string): string => {
  if (data.startsWith("0x")) {
    return data;
  }
  return "0x" + data;
};
