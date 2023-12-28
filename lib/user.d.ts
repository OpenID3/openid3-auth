import * as functions from "firebase-functions";
/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   address?: string, // only valid if registered is true
 */
export declare const getAddressByUid: functions.HttpsFunction;
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
export declare const getUserByUid: functions.HttpsFunction;
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
export declare const getUserByAddress: functions.HttpsFunction;
