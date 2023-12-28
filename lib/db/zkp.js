"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.markZkProofError = exports.addZkProof = exports.addNewZkpRequest = exports.getZkp = void 0;
const firestore_1 = require("firebase-admin/firestore");
const utils_1 = require("./utils");
const utils_2 = require("../utils");
async function getZkp(uid) {
    const result = await (0, utils_1.firestore)().collection("zkp").doc(uid).get();
    if (result && result.exists) {
        return result.data();
    }
    return null;
}
exports.getZkp = getZkp;
async function addNewZkpRequest(uid, jwtInput, chain, userOp) {
    await (0, utils_1.firestore)()
        .collection("zkp")
        .doc(uid)
        .set({
        status: "processing",
        jwtInput,
        chain,
        userOp,
        createdAt: new firestore_1.Timestamp((0, utils_2.epoch)(), 0),
    });
}
exports.addNewZkpRequest = addNewZkpRequest;
async function addZkProof(uid, proof) {
    await (0, utils_1.firestore)().collection("zkp").doc(uid).update({
        status: "done",
        proof,
    });
}
exports.addZkProof = addZkProof;
async function markZkProofError(uid, error) {
    await (0, utils_1.firestore)().collection("zkp").doc(uid).update({
        status: "error",
        error,
    });
}
exports.markZkProofError = markZkProofError;
//# sourceMappingURL=zkp.js.map