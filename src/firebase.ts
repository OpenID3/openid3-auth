import * as admin from "firebase-admin";
import { initializeFirestore } from "firebase-admin/firestore";
import * as functions from "firebase-functions";

admin.initializeApp();
const secrets = functions.config().doppler || {};

export class PrivateFirebase {
  app : admin.app.App;
  db: admin.firestore.Firestore;
  storage: admin.storage.Storage;
  database: admin.database.Database;
  auth: admin.auth.Auth;

  constructor() {
    this.app = admin.app();
    if (secrets.ENV === "dev") {
      this.db = initializeFirestore(this.app, {}, "test");
    } else {
      this.db = admin.firestore();
    }
    this.storage = admin.storage();
    this.database = admin.database();
    this.auth = admin.auth();
  }
}

export class Firebase {
  private static instance : PrivateFirebase;

  private constructor() {
    throw new Error("Use Firebase.getInstance()");
  }

  static getInstance() {
    if (!Firebase.instance) {
      Firebase.instance = new PrivateFirebase();
    }
    return Firebase.instance;
  }
}
