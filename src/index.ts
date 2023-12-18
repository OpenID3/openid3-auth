import * as admin from "firebase-admin";
admin.initializeApp();

import * as auth from "./auth";
import * as zkp from "./zkp";

exports.getAddressByUid = auth.getAddressByUid;
exports.getUserByUid = auth.getUserByUid;
exports.getUserByAddress = auth.getUserByAddress;
exports.registerUserWithPasskey = auth.registerUserWithPasskey;
exports.getPasskeyChallenge = auth.getPasskeyChallenge;
exports.loginWithPasskey = auth.loginWithPasskey;
exports.sessionLogin = auth.sessionLogin;
exports.encrypt = auth.encrypt;
exports.getDek = auth.getDek;

exports.requestToReset = zkp.requestToReset;
exports.queryResetStatus = zkp.queryResetStatus;
exports.submitZkProof = zkp.submitZkProof;
