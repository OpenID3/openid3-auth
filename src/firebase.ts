import * as admin from "firebase-admin";
admin.initializeApp();

export class PrivateFirebase {
  app : admin.app.App;
  db: admin.firestore.Firestore;
  storage: admin.storage.Storage;
  database: admin.database.Database;
  auth: admin.auth.Auth;

  constructor() {
    this.app = admin.app();
    this.db = admin.firestore();
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
