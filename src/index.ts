import * as auth from "./auth";

exports.isNameRegistered = auth.isNameRegistered;
exports.registerUserWithPasskey = auth.registerUserWithPasskey;
exports.getPasskeyChallenge = auth.getPasskeyChallenge;
exports.loginWithPasskey = auth.loginWithPasskey;
exports.getDataEncryptionKey = auth.getDataEncryptionKey;
