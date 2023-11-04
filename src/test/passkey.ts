import { secp256r1 } from "@noble/curves/p256";
import crypto from "crypto";

export const genPasskey = (): any => {
    // const privKey = secp256r1.utils.randomPrivateKey();
    const privKey = Buffer.from("d6988c4f34d49d49818a312c706ef9104de0bebd8a10614aa7708681e6f25dd7", "hex");
    const pubKey = secp256r1.getPublicKey(privKey);
    return { privKey, pubKey };
}

export const signWithPasskey = (data: any, passkey: any) => {
    const challenge = crypto.createHash("sha256").update(
        JSON.stringify(data)
    ).digest("hex");
    console.log("challenge", challenge);
    const clientDataJson = JSON.stringify({
        challenge: challenge,
        origin: "https://openid3.org",
        somekey: "somevalue",
    });
    const clientDataHash = crypto.createHash("sha256")
      .update(clientDataJson)
      .digest();
    const authData = Buffer.concat([
        Buffer.from(passkey.pubKey),
        // sha256("somerandomdata")
        Buffer.from("dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0", "hex"),
    ]);
    const signedData = Buffer.concat([
        authData,
        clientDataHash,
    ]);
    const signedDataHash = crypto.createHash("sha256")
        .update(signedData)
        .digest("hex");
    console.log("signedDataHash", signedDataHash);
    const signature = secp256r1.sign(signedDataHash, passkey.privKey);
    return {
        clientDataJson,
        authData: authData.toString("hex"),
        signature,
    }
};

export const signRegisterRequest = (uid: string, passkey: any) => {
    return signWithPasskey({
        action: "register",
        uid,
    }, passkey);
}