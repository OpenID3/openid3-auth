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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getUserByAddress = exports.getUserByUid = exports.getAddressByUid = void 0;
const cors_1 = __importDefault(require("cors"));
const functions = __importStar(require("firebase-functions"));
const utils_1 = require("./utils");
const ratelimiter_1 = require("./ratelimiter");
const ns_1 = require("./db/ns");
const user_1 = require("./db/user");
const secrets = functions.config().doppler || {};
/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   address?: string, // only valid if registered is true
 */
exports.getAddressByUid = functions.https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            if (secrets.ENV !== "dev" && (await (0, ratelimiter_1.checkNameRateLimit)(req.ip || ""))) {
                throw new utils_1.HexlinkError(429, "Too many requests");
            }
            const address = await (0, ns_1.resolveName)(req.body.uid);
            if (!address) {
                res.status(200).json({ registered: false });
            }
            else {
                res.status(200).json({ registered: true, address });
            }
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
        }
    });
});
/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   user?: { // only valid if registered is true
 *     address: string,
 *     factory: string,
 *     operator: string,
 *     metadata: string,
 *     passkey: Passkey,
 *   }
 */
exports.getUserByUid = functions.https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            if (secrets.ENV !== "dev" && (await (0, ratelimiter_1.checkNameRateLimit)(req.ip || ""))) {
                throw new utils_1.HexlinkError(429, "Too many requests");
            }
            const address = await (0, ns_1.resolveName)(req.body.uid);
            if (!address) {
                res.status(200).json({ registered: false });
            }
            else {
                const user = await (0, user_1.getUser)(address);
                if (user) {
                    res.status(200).json({
                        registered: true,
                        user: {
                            address,
                            factory: user.factory,
                            passkey: user.passkey,
                            operator: user.operator,
                            metadata: user.metadata,
                        },
                    });
                }
                else {
                    throw new utils_1.HexlinkError(500, "user data lost");
                }
            }
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
        }
    });
});
/**
 * req.body: {
 *   address: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   user?: { // only valid if registered is true
 *     address: string,
 *     factory: string,
 *     operator: string,
 *     metadata: string,
 *     passkey: Passkey,
 *   }
 */
exports.getUserByAddress = functions.https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            if (secrets.ENV !== "dev" && (await (0, ratelimiter_1.checkNameRateLimit)(req.ip || ""))) {
                throw new utils_1.HexlinkError(429, "Too many requests");
            }
            const user = await (0, user_1.getUser)(req.body.address);
            if (user) {
                res.status(200).json({
                    registered: true,
                    user: {
                        address: req.body.address,
                        factory: user.factory,
                        passkey: user.passkey,
                        operator: user.operator,
                        metadata: user.metadata,
                    },
                });
            }
            else {
                throw new utils_1.HexlinkError(404, "user not found");
            }
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
        }
    });
});
//# sourceMappingURL=user.js.map