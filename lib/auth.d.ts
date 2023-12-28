import * as functions from "firebase-functions";
/**
 * req.body: {
 *  username: string,
 *  factory: string,
 *  operator: string,
 *  metadata: string,
 *  passkey: {
 *    id: string,
 *    x: string,
 *    y: string,
 *  },
 *  clientDataJson: string,
 *  authData: string, // hex
 *  signature: string, // hex
 *  dek: string,
 * }
 *
 * res: {
 *   token: string,
 *   address: string,
 *   csrfToken: string,
 *   encDek: string,
 * }
 */
export declare const registerUserWithPasskey: functions.HttpsFunction;
/**
 * req.body: {
 *   address: string,
 * }
 *
 * res: {
 *   challenge: string, // hex
 * }
 */
export declare const getPasskeyChallenge: functions.HttpsFunction;
export declare const loginWithPasskey: functions.HttpsFunction;
/**
 * req.body: {
 *   idToken: string,
 *   csrfToken: string,
 * }
 *
 * res: {
 *   success: true,
 * }
 */
export declare const sessionLogin: functions.HttpsFunction;
/**
 * req.body: {
 *   encDek: string, // to decrypt
 *   newDek?: string, // to encrypt
 *   csrfToken: string,
 * }
 *
 * res: {
 *   dek: string, // decrypted
 *   encNewDek?: string, // encrypted
 * }
 */
export declare const getDeks: functions.HttpsFunction;
export declare const verifySessionCookie: (req: functions.Request) => Promise<import("firebase-admin/lib/auth").DecodedIdToken>;
