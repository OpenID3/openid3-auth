import * as admin from "firebase-admin";
import { applicationDefault } from "firebase-admin/app";

admin.initializeApp({
  projectId: process.env.FIREBASE_PROJECT_ID!,
  credential: applicationDefault(),
  databaseURL: "https://mizu-ad285-default-rtdb.firebaseio.com"
});

export const db = admin.firestore();

export const coll = (coll: string) => {
  return db.collection(coll + "_" + process.env.ENV);
}
