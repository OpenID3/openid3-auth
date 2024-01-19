import * as admin from "firebase-admin";
import * as functions from "firebase-functions";

const secrets = functions.config().doppler || {};

export const firestore = () => {
  return admin.firestore();
};

export const coll = (coll: string) => {
  return firestore().collection(coll + "_" + secrets.ENV);
};

export interface Passkey {
  x: string; // pubKeyX
  y: string; // pubKeyY
  id: string;
}
