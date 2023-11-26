import * as admin from "firebase-admin";
admin.initializeApp();

import * as auth from "./auth";
import * as zkp from "./zkp";

exports.getUserByUid = auth.getUserByUid;
exports.registerUserWithPasskey = auth.registerUserWithPasskey;
exports.getPasskeyChallenge = auth.getPasskeyChallenge;
exports.loginWithPasskey = auth.loginWithPasskey;
exports.getDataEncryptionKey = auth.getDataEncryptionKey;

exports.requestToReset = zkp.requestToReset;
exports.queryResetStatus = zkp.queryResetStatus;
exports.submitZkProof = zkp.submitZkProof;
