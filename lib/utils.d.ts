/// <reference types="node" />
import * as functions from "firebase-functions";
export declare const epoch: () => number;
export declare class HexlinkError extends Error {
    code: number;
    constructor(code: number, message: string);
}
export declare const handleError: (res: functions.Response, err: unknown) => void;
export declare const sha3: (data: string | Buffer) => Buffer;
export declare const sha256: (data: string | Buffer) => Buffer;
export declare const INVALID_USER_NAME_TOO_SHORT = "invalid username: must be at least 5 characters";
export declare const INVALID_USER_NAME_EMTPY_LABEL = "invalid username: empty label";
export declare const INVALID_USER_NAME_DISALLOWED_CHARACTERS = "invalid username: disallowed characters";
export declare const INVALID_USER_NAME_NON_MIZU_NAME = "invalid username: must end with mizu";
export declare const SUBDOMAIN_NOT_ALLOWED = "invalid username: subdomain not allowed";
export declare const genNameHash: (username: string) => string;
export declare const toBuffer: (data: string) => Buffer;
export declare const formatHex: (data: string) => string;
