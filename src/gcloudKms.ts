/* eslint-disable require-jsdoc */
import * as kms from "@google-cloud/kms";
import * as crc32c from "fast-crc32c";
import * as functions from "firebase-functions";

const secrets = functions.config().doppler;
const client = new kms.KeyManagementServiceClient();

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
      config.keyId);
};

export const encryptWithSymmKey = async function(plaintext: string) {
  const plaintextBuffer = Buffer.from(plaintext);
  const keyName = await getSymmKeyName();
  const plaintextCrc32c = crc32c.calculate(plaintextBuffer);

  const [encryptResponse] = await client.encrypt({
    name: keyName,
    plaintext: plaintextBuffer,
    plaintextCrc32c: {
      value: plaintextCrc32c,
    },
  });

  const ciphertext = encryptResponse.ciphertext;

  if (!ciphertext || !encryptResponse.verifiedPlaintextCrc32c ||
    !encryptResponse.ciphertextCrc32c ||
    crc32c.calculate(ciphertext) !==
    Number(encryptResponse.ciphertextCrc32c!.value)) {
    throw new Error("Encrypt: request corrupted in-transit");
  }

  return Buffer.from(ciphertext).toString("base64");
};

export const decryptWithSymmKey = async function(text: string) {
  const ciphertext = Buffer.from(text, "base64");
  const keyName = await getSymmKeyName();
  const ciphertextCrc32c = crc32c.calculate(ciphertext);

  const [decryptResponse] = await client.decrypt({
    name: keyName,
    ciphertext: ciphertext,
    ciphertextCrc32c: {
      value: ciphertextCrc32c,
    },
  });
  const plaintextBuffer = Buffer.from(decryptResponse.plaintext!);

  if (crc32c.calculate(plaintextBuffer) !==
      Number(decryptResponse.plaintextCrc32c!.value)) {
    throw new Error("Decrypt: response corrupted in-transit");
  }

  return plaintextBuffer.toString("utf8");
};