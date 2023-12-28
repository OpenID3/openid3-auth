"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.userExist = exports.getUser = void 0;
const utils_1 = require("./utils");
async function getUser(address) {
    const result = await (0, utils_1.firestore)().collection("users").doc(address).get();
    if (result && result.exists) {
        return result.data();
    }
    return null;
}
exports.getUser = getUser;
async function userExist(address) {
    const result = await (0, utils_1.firestore)().collection("users").doc(address).get();
    if (result && result.exists) {
        return true;
    }
    return false;
}
exports.userExist = userExist;
//# sourceMappingURL=user.js.map