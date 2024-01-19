import * as admin from "firebase-admin";
import { applicationDefault } from "firebase-admin/app";

admin.initializeApp({
  credential: applicationDefault(),
  databaseURL: "https://mizu-ad285-default-rtdb.firebaseio.com"
});

export const db = admin.firestore();