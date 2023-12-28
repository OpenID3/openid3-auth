"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.resolveName = void 0;
const utils_1 = require("./utils");
async function resolveName(uid) {
    const name = await (0, utils_1.firestore)().collection("mns").doc(uid).get();
    if (name && name.exists) {
        return name.data().address;
    }
    return null;
}
exports.resolveName = resolveName;
//# sourceMappingURL=ns.js.map