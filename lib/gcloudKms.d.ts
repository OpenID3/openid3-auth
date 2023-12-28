export declare const encryptWithSymmKey: (plaintext: string, aad: Buffer) => Promise<string | undefined>;
export declare const decryptWithSymmKey: (text: string | undefined, aad: Buffer) => Promise<string | undefined>;
