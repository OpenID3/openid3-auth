"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rateLimiter = exports.getChallengeRateLimit = exports.checkNameRateLimit = exports.registerRateLimit = void 0;
const admin = __importStar(require("firebase-admin"));
const txServiceRateDBRef = "functions/rates/";
const timestampKey = "timestamp";
async function registerRateLimit(ip) {
    return await (0, exports.rateLimiter)("sign_up", `ip_${ip}`, 60, 10);
}
exports.registerRateLimit = registerRateLimit;
async function checkNameRateLimit(ip) {
    return await (0, exports.rateLimiter)("check_name", `ip_${ip}`, 60, 30);
}
exports.checkNameRateLimit = checkNameRateLimit;
async function getChallengeRateLimit(ip) {
    return await (0, exports.rateLimiter)("get_challenge", `ip_${ip}`, 60, 30);
}
exports.getChallengeRateLimit = getChallengeRateLimit;
const rateLimiter = async (callName, rawId, windowInSec, threshold) => {
    const callRef = txServiceRateDBRef + callName;
    const ref = admin.database().ref(callRef);
    const id = rawId.replace(/\/|\.|#|$/g, ":");
    const now = Date.now();
    const snapshot = await ref.child(`${id}`).get();
    if (snapshot.exists()) {
        const snapVal = snapshot.val();
        const tsMap = new Map(Object.entries(JSON.parse(snapVal)));
        if (!tsMap.has(timestampKey)) {
            addRecord(id, [now], ref);
            return false;
        }
        const tsList = tsMap.get(timestampKey);
        const tsThre = now - 1000 * windowInSec;
        const tsInWindow = tsList.filter((ts) => ts > tsThre);
        tsInWindow.push(now);
        addRecord(id, tsInWindow, ref);
        return tsInWindow.length > threshold;
    }
    else {
        addRecord(id, [now], ref);
        return false;
    }
};
exports.rateLimiter = rateLimiter;
const addRecord = (id, timestampList, ref) => {
    const timestampMap = new Map([
        [timestampKey, timestampList],
    ]);
    const timestampObj = Object.fromEntries(timestampMap);
    ref.update({ [`${id}`]: JSON.stringify(timestampObj) });
};
//# sourceMappingURL=ratelimiter.js.map