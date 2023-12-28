/* eslint-disable require-jsdoc */
import * as kms from "@google-cloud/kms";
import * as crc32c from "fast-crc32c";
import * as functions from "firebase-functions";
import crypto from "crypto";

const secrets = functions.config().doppler;
const client = new kms.KeyManagementServiceClient();
const DEV_ENC_ALGORITHM = "aes-256-gcm";

const encryptorConfig = () => ({
  projectId: secrets.FIREBASE_PROJECT_ID,
  locationId: secrets.GCP_KEY_LOCATION_GLOBAL,
  keyRingId: secrets.ENCRYPTOR_KEY_RING_ID,
  keyId: secrets.ENCRYPTOR_KEY_ID,
});

const getSymmKeyName = async function() {
  const config = encryptorConfig();
  return client.cryptoKeyPath(
      config.projectId,
      config.locationId,
      config.keyRingId,
      config.keyId
  );
};

const encryptWithDevKey = (plaintext: string, aad: Buffer) => {
  const key = Buffer.from(secrets.DEV_KEY, "hex");
  const iv = Buffer.from(secrets.DEV_KEY_IV, "hex");
  const cipher = crypto.createCipheriv(DEV_ENC_ALGORITHM, key, iv);
  cipher.setAAD(aad);
  const encrypted = cipher.update(plaintext);
  const result = Buffer.concat([encrypted, cipher.final()]).toString("base64");
  return JSON.stringify({
    encrypted: result,
    authTag: cipher.getAuthTag().toString("hex"),
  });
};

const decryptWithDevKey = (text: string, aad: Buffer) => {
  const {encrypted, authTag} = JSON.parse(text);
  const ciphertext = Buffer.from(encrypted, "base64");
  const key = Buffer.from(secrets.DEV_KEY, "hex");
  const iv = Buffer.from(secrets.DEV_KEY_IV, "hex");
  const decipher = crypto.createDecipheriv(DEV_ENC_ALGORITHM, key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  const decrypted = decipher.update(ciphertext);
  return Buffer.concat([decrypted, decipher.final()]).toString("utf-8");
};

export const encryptWithSymmKey = async function(
    plaintext: string,
    aad: Buffer
) {
  if (plaintext === undefined) {
    return undefined;
  }
  if (secrets.ENV === "dev") {
    return encryptWithDevKey(plaintext, aad);
  }
  const plaintextBuffer = Buffer.from(plaintext);
  const keyName = await getSymmKeyName();
  const plaintextCrc32c = crc32c.calculate(plaintextBuffer);

  const [encryptResponse] = await client.encrypt({
    name: keyName,
    plaintext: plaintextBuffer,
    additionalAuthenticatedData: aad,
    plaintextCrc32c: {
      value: plaintextCrc32c,
    },
  });

  const ciphertext = encryptResponse.ciphertext;

  if (
    !ciphertext ||
    !encryptResponse.verifiedPlaintextCrc32c ||
    !encryptResponse.ciphertextCrc32c ||
    crc32c.calculate(ciphertext) !==
      Number(encryptResponse.ciphertextCrc32c!.value)
  ) {
    throw new Error("Encrypt: request corrupted in-transit");
  }

  return Buffer.from(ciphertext).toString("base64");
};

export const decryptWithSymmKey = async function(
    text: string | undefined,
    aad: Buffer
) {
  if (text === undefined) {
    return undefined;
  }
  if (secrets.ENV === "dev") {
    return decryptWithDevKey(text, aad);
  }
  const ciphertext = Buffer.from(text, "base64");
  const keyName = await getSymmKeyName();
  const ciphertextCrc32c = crc32c.calculate(ciphertext);
  const [decryptResponse] = await client.decrypt({
    name: keyName,
    additionalAuthenticatedData: aad,
    ciphertext: ciphertext,
    ciphertextCrc32c: {
      value: ciphertextCrc32c,
    },
  });
  const plaintextBuffer = Buffer.from(decryptResponse.plaintext!);

  if (
    crc32c.calculate(plaintextBuffer) !==
    Number(decryptResponse.plaintextCrc32c!.value)
  ) {
    throw new Error("Decrypt: response corrupted in-transit");
  }

  return plaintextBuffer.toString("utf8");
};