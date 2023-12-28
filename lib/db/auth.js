"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerUser = exports.postAuth = exports.preAuth = exports.getAuth = void 0;
const firestore_1 = require("firebase-admin/firestore");
const utils_1 = require("./utils");
const utils_2 = require("../utils");
async function getAuth(address) {
    const result = await (0, utils_1.firestore)().collection("auth").doc(address).get();
    if (result && result.exists) {
        return result.data();
    }
    return null;
}
exports.getAuth = getAuth;
async function preAuth(address, challenge) {
    await (0, utils_1.firestore)()
        .collection("auth")
        .doc(address)
        .update({
        challenge: challenge,
        updatedAt: new firestore_1.Timestamp((0, utils_2.epoch)(), 0),
    });
}
exports.preAuth = preAuth;
async function postAuth(address, csrfToken) {
    await (0, utils_1.firestore)()
        .collection("auth")
        .doc(address)
        .update({
        challenge: null,
        updatedAt: new firestore_1.Timestamp((0, utils_2.epoch)(), 0),
        csrfToken,
    });
}
exports.postAuth = postAuth;
async function registerUser(uid, address, passkey, factory, operator, metadata, csrfToken) {
    const db = (0, utils_1.firestore)();
    const nsRef = db.collection("mns").doc(uid);
    const userRef = db.collection("users").doc(address);
    const authRef = db.collection("auth").doc(address);
    await db.runTransaction(async (t) => {
        const doc = await t.get(nsRef);
        if (doc && doc.exists) {
            throw new utils_2.HexlinkError(400, "name already taken");
        }
        t.set(nsRef, { address });
        t.set(userRef, {
            passkey,
            factory,
            operator,
            metadata,
            createdAt: new firestore_1.Timestamp((0, utils_2.epoch)(), 0),
        });
        t.set(authRef, {
            passkey,
            csrfToken,
            updatedAt: new firestore_1.Timestamp((0, utils_2.epoch)(), 0),
        });
    });
}
exports.registerUser = registerUser;
//# sourceMappingURL=auth.js.map