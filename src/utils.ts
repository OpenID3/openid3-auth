import {ethers} from "ethers";
import * as functions from "firebase-functions";

export const hash = (message: string) => {
  return ethers.keccak256(ethers.toUtf8Bytes(message));
};

export const epoch = () => {
  return Math.floor(new Date().getTime() / 1000);
};

export const toEthSignedMessageHash = function(messageHex: string) {
  return ethers.keccak256(
      ethers.solidityPacked(["string", "bytes32"],
          ["\x19Ethereum Signed Message:\n32", messageHex]));
};

export const DAUTH_JWK = {
  "kty": "EC",
  "crv": "P-256",
  "x": "G1kL6UJ85jAXwC40y-YFdjn4PEluaRvWQQYG1sDcNao",
  "y": "a66lvKe4rCiwbQUxqjFZT8R-0xdGEJgeGXtNC9XclaY",
};

export class HexlinkError extends Error {
  code: number;

  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export function getAuthToken(req: functions.https.Request) {
  const authZ = req.get("Authorization");
  if (authZ) {
    const tokens = authZ.split("Bearer ");
    if (tokens.length > 1) {
      return tokens[1];
    }
  }
  return req.body.authToken;
}

export const handleError = function(
    res: functions.Response,
    err: unknown
) {
  if (err instanceof HexlinkError) {
    res.status(err.code).json({message: err.message});
  }
  console.log("Error: ", err);
  res.status(500).json({message: "internal server error"});
};

export function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export function emailHash(email: string) {
  const normalized = normalizeEmail(email);
  return hash(`mailto:${normalized}`);
}

export function maskEmail(email: string) {
  const normalized = normalizeEmail(email);
  const [name, domain] = normalized.split("@");
  return `${name[0]}***@${domain}`;
}
