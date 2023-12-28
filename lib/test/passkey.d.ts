/// <reference types="node" />
import { PrivateKey } from "eciesjs";
import { Passkey } from "../db/utils";
export interface Key {
    privKey: Uint8Array | Buffer;
    pubKey: Passkey;
}
export declare const genPasskey: (id: string) => Key;
export declare const signWithPasskey: (challenge: any, origin: string, passkey: any) => {
    clientDataJson: string;
    authData: string;
    signature: import("@noble/curves/abstract/weierstrass").RecoveredSignatureType;
};
export declare const signRegisterRequest: (username: string, origin: string, factory: string, passkey: any, operator: string, metadata: string, dek: string) => {
    clientDataJson: string;
    authData: string;
    signature: import("@noble/curves/abstract/weierstrass").RecoveredSignatureType;
};
export declare const signLoginRequest: (address: string, origin: string, challenge: string, passkey: any, dek: string, newDek?: string) => {
    clientDataJson: string;
    authData: string;
    signature: import("@noble/curves/abstract/weierstrass").RecoveredSignatureType;
};
export declare const genEciesKey: () => {
    privKey: PrivateKey;
    pubKey: string;
};
