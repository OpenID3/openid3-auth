import * as admin from "firebase-admin";
admin.initializeApp();

import * as auth from "./auth";
import * as user from "./user";

exports.getAddressByUid = user.getAddressByUid;
exports.getUserByAddress = user.getUserByAddress;
exports.getUserByUid = user.getUserByUid;

exports.registerUserWithPasskey = auth.registerUserWithPasskey;
exports.getPasskeyChallenge = auth.getPasskeyChallenge;
exports.loginWithPasskey = auth.loginWithPasskey;
exports.sessionLogin = auth.sessionLogin;
exports.getDeks = auth.getDeks;
