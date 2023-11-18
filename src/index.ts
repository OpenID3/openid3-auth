import * as auth from "./auth";
import * as zkp from "./zkp";

exports.isNameRegistered = auth.isNameRegistered;
exports.registerUserWithPasskey = auth.registerUserWithPasskey;
exports.getPasskeyChallenge = auth.getPasskeyChallenge;
exports.loginWithPasskey = auth.loginWithPasskey;
exports.getDataEncryptionKey = auth.getDataEncryptionKey;

exports.requestZkProof = zkp.requestZkProof;
exports.queryZkProof = zkp.queryZkProof;
exports.storeZkProof = zkp.storeZkProof;
