import { ethers, toUtf8Bytes } from "ethers";
import { HexString, HexlinkError } from "./types";

export const INVALID_USER_NAME_TOO_SHORT =
  "invalid username: must be at least 5 characters";
export const INVALID_USER_NAME_ = "invalid username: empty label";
export const INVALID_USER_NAME_DISALLOWED_CHARACTERS =
  "invalid username: disallowed characters";
export const INVALID_USER_NAME_ALREADY_REGISTERED =
  "invalid username: already registered";
export const INVALID_USER_NAME_NOT_REGISTERED =
  "invalid username: not registered";

const validateMizuName = (name: string) => {
  const labels = name.split(".");
  if (labels.length !== 2) {
    throw new HexlinkError(400, INVALID_USER_NAME_TOO_SHORT);
  }
  if (labels[0].length < 5) {
    throw new HexlinkError(400, INVALID_USER_NAME_TOO_SHORT);
  }
  if (!/^[a-z0-9]+$/.test(labels[0])) {
    throw new HexlinkError(400, INVALID_USER_NAME_DISALLOWED_CHARACTERS);
  }
};

const nameHash = (name: string): string => {
  if (name == "") {
    return ethers.ZeroHash;
  }
  const index = name.indexOf(".");
  if (index === -1) {
    return ethers.solidityPackedKeccak256(
      ["bytes32", "bytes32"],
      [nameHash(""), ethers.keccak256(toUtf8Bytes(name))]
    );
  } else {
    const label = name.slice(0, index);
    const remainder = name.slice(index + 1);
    return ethers.solidityPackedKeccak256(
      ["bytes32", "bytes32"],
      [nameHash(remainder), ethers.keccak256(toUtf8Bytes(label))]
    );
  }
};

export const genNameHash = (username: string) => {
  username = username.trim().toLowerCase();
  if (!username.endsWith(".mizu")) {
    username = username + ".mizu";
  }
  validateMizuName(username);
  return nameHash(username) as HexString;
};
