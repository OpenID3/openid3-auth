import * as functions from "firebase-functions";
/**
 * req.body: {
 *   provider: "google",
 *   idToken: string,
 *   chain: Chain,
 *   userOp: UserOpStruct,
 *   dev: boolean,
 * }
 *
 * res: {
 *   status: "processing" | "error" | "done";
 * }
 */
export declare const requestToReset: functions.HttpsFunction;
/**
 * req.body: {
 *    chain: Chain,
 * }
 *
 * res: {
 *    status: "processing" | "error" | "done",
 *    userOpHash: string,
 *    error?: string,
 * }
 */
export declare const queryResetStatus: functions.HttpsFunction;
/**
 * req.body: {
 *   uid: string;
 *   idToken: string;
 *   success: boolean,
 *   proof?: OidcZkProof,
 *   error?: string,
 * }
 *
 * res: {
 *   success: boolean,
 * }
 *
 * This can only be called by the zkp service.
 */
export declare const submitZkProof: functions.HttpsFunction;
