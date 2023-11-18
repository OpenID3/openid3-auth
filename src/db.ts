import * as admin from "firebase-admin";
import {epoch, sha256} from "./utils";
import {Timestamp} from "firebase-admin/firestore";

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

const firestore = () => {
  return admin.firestore();
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

export interface ZKP {
    uid: string;
    idTokenHash: string;
    status: "processing" | "done" | "error";
    proof: string | null; // for done status
    error: string | null; // for error status
    createdAt: Timestamp;
    finishedAt: Timestamp | null;
}

export async function getZkp(
    uid: string,
) : Promise<ZKP | null> {
  const result = await firestore().collection("zkp").doc(uid).get();
  if (result && result.exists) {
    return result.data() as ZKP;
  }
  return null;
}

export async function postZkpRequest(
    uid: string,
    idToken: string,
) {
  await firestore().collection("zkp").doc(uid).update({
    status: "processing",
    idTokenHash: sha256(idToken),
  });
}

export async function addZkProof(
    uid: string,
    idToken: string,
    status: "processing" | "done" | "error",
    proof: string | null,
    error: string | null,
) {
  await firestore().collection("zkp").doc(uid).update({
    status,
    idTokenHash: sha256(idToken),
    proof,
    error,
  });
}
