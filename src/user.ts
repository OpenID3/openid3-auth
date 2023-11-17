/* Database */

import {Timestamp} from "@google-cloud/firestore";
import * as admin from "firebase-admin";
import {HexlinkError, epoch} from "./utils";
import {ethers} from "ethers";

const firestore = () => {
  return admin.firestore();
};

export interface User {
    passkey: {x: string, y: string}; // hex version of public key
    kek: string, // stored at client side to decrypt the dek from server
    deks: {[key: string]: string},
    loginStatus: {
        challenge: string,
        updatedAt: Timestamp,
    }
    createdAt: Timestamp;
}

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

export async function createUser(
    uid: string,
    passkey: string,
    kek: string,
    deks: {[key: string]: string}
) {
  await firestore().collection("users").doc(uid).set({
    passkey,
    kek,
    deks,
    createdAt: new Timestamp(epoch(), 0),
    loginStatus: {
      challenge: "",
      updatedAt: new Timestamp(epoch(), 0),
    },
  });
}

export async function getUser(
    uid: string,
) : Promise<User | null> {
  const result = await firestore().collection("users").doc(uid).get();
  if (result && result.exists) {
    return result.data() as User;
  }
  return null;
}

export async function userExist(
    uid: string,
) : Promise<boolean> {
  const result = await firestore().collection("users").doc(uid).get();
  if (result && result.exists) {
    return true;
  }
  return false;
}

export async function preAuth(uid: string, challenge: string) {
  await firestore().collection("users").doc(uid).update({
    loginStatus: {
      challenge: challenge,
      updatedAt: new Timestamp(epoch(), 0),
    },
  });
}

export async function postAuth(
    uid: string,
    kek: string,
    deks: {[key: string]: string}
) {
  await firestore().collection("users").doc(uid).update({
    kek,
    deks,
    loginStatus: {
      challenge: "",
      updatedAt: new Timestamp(epoch(), 0),
    },
  });
}

export async function updateDeks(
    uid: string,
    deks: {[key: string]: string}
) {
  await firestore().collection("users").doc(uid).update({deks});
}
