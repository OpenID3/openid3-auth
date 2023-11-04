import * as admin from "firebase-admin";

admin.initializeApp();

import * as auth from "./auth";

exports.registerUserWithPasskey = auth.registerUserWithPasskey;
exports.getPasskeyChallenge = auth.getPasskeyChallenge;
exports.loginWithPasskey = auth.loginWithPasskey;
exports.getDataEncryptionKey = auth.getDataEncryptionKey;
