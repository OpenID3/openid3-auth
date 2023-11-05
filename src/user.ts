/* Database */

import { Timestamp } from "@google-cloud/firestore";
import * as admin from "firebase-admin";
import { HexlinkError, epoch } from "./utils";
import crypto from "crypto";

const firestore = () => {
    return admin.firestore();
}

export interface User {
    passkey: string; // public key of passkey
    kek: string, // stored at client side to decrypt the dek from server
    deks: string[], // stored at server side
    loginStatus: {
        step: "challenge" | "loggedin" | "loggedout",
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

export const genNameHash = (username: string) => {
  username = username.trim().toLowerCase();
  validateUsername(username);
  const finalName = username + ".id";
  return nameHash(finalName).toString("hex");
}

const validateUsername = (username: string) => {
  if (username.length < 5) {
    throw new HexlinkError(400, INVALID_USER_NAME_TOO_SHORT);
  }
  let labels = username.split(".");
  for (const label of labels) {
    if (label.length == 0) {
      throw new HexlinkError(400, INVALID_USER_NAME_EMTPY_LABEL);
    }
    if (!/^[a-z0-9]+$/.test(label)) {
      throw new HexlinkError(400, INVALID_USER_NAME_DISALLOWED_CHARACTERS);
    }
  }
  return username;
}

const sha3 = (data: string | Buffer) : Buffer => {
  return crypto.createHash("sha3-256").update(data).digest();
}

const nameHash = (name: string) : Buffer => {
  if (name == "") {
    return Buffer.from("0000000000000000000000000000000000000000000000000000000000000000", "hex");
  }
  const index = name.indexOf(".");
  if (index === -1) {
    return sha3(Buffer.concat([nameHash(""), sha3(name)]));
  } else {
    const label = name.slice(0, index);
    const remainder = name.slice(index + 1);
    return sha3(Buffer.concat([nameHash(remainder), sha3(label)]));
  }
}

export async function createUser(
  uid: string,
  passkey: string,
  dek: string
) {
  await firestore().collection("users").doc(uid).set({
    passkey: passkey,
    deks: [dek],
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

export async function preAuth(uid: string, challenge: string) {
  await firestore().collection("users").doc(uid).update({
    loginStatus: {
      challenge: challenge,
      updatedAt: new Timestamp(epoch(), 0),
    },
  });
}

export async function postAuth(uid: string) {
  await firestore().collection("users").doc(uid).update({
    loginStatus: {
      challenge: "",
      updatedAt: new Timestamp(epoch(), 0),
    },
  });
}

export async function rotateDek(uid: string, oldDek: string, newDek: string) {
  await firestore().collection("users").doc(uid).update({
    deks: [oldDek, newDek],
  });
}