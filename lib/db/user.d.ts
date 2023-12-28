import { Timestamp } from "firebase-admin/firestore";
import { Passkey } from "./utils";
export interface User {
    passkey: Passkey;
    factory: string;
    operator: string;
    metadata: string;
    createdAt: Timestamp;
}
export declare function getUser(address: string): Promise<User | null>;
export declare function userExist(address: string): Promise<boolean>;
