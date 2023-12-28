import { Timestamp } from "firebase-admin/firestore";
import { Passkey } from "./utils";
export interface Auth {
    passkey: Passkey;
    challenge: string | null;
    csrfToken: string;
    updatedAt: Timestamp;
}
export declare function getAuth(address: string): Promise<Auth | null>;
export declare function preAuth(address: string, challenge: string): Promise<void>;
export declare function postAuth(address: string, csrfToken: string): Promise<void>;
export declare function registerUser(uid: string, address: string, passkey: Passkey, factory: string, operator: string, metadata: string, csrfToken: string): Promise<void>;
