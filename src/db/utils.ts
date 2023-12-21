import * as admin from "firebase-admin";

export const firestore = () => {
  return admin.firestore();
};

export interface Passkey {
  x: string; // pubKeyX
  y: string; // pubKeyY
  id: string;
}
