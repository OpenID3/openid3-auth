/* Database */

import { Timestamp } from "@google-cloud/firestore";
import * as admin from "firebase-admin";
import { epoch } from "./utils";

const firestore = () => {
    return admin.firestore();
}

interface User {
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

export async function getUser(
    uid: string,
) : Promise<User | null> {
  const result = await firestore().collection("users").doc(uid).get();
  if (result && result.exists) {
    return result.data() as User;
  }
  return null;
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
  await admin.auth().createUser({uid});
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