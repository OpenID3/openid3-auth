import * as admin from "firebase-admin";
export declare const firestore: () => admin.firestore.Firestore;
export interface Passkey {
    x: string;
    y: string;
    id: string;
}
