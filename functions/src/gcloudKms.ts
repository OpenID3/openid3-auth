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

const getSymmKeyName = async () => {
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
  const { encrypted, authTag } = JSON.parse(text);
  const ciphertext = Buffer.from(encrypted, "base64");
  const key = Buffer.from(secrets.DEV_KEY, "hex");
  const iv = Buffer.from(secrets.DEV_KEY_IV, "hex");
  const decipher = crypto.createDecipheriv(DEV_ENC_ALGORITHM, key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  const decrypted = decipher.update(ciphertext);
  return Buffer.concat([decrypted, decipher.final()]).toString("utf-8");
};

export const encryptWithSymmKey = async (
  plaintext: string,
  aad: Buffer
) => {
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

export const decryptWithSymmKey = async (
  text: string | undefined,
  aad: Buffer
) => {
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

const jwtSignerConfig = () => ({
  projectId: secrets.FIREBASE_PROJECT_ID,
  locationId: secrets.GCP_KEY_LOCATION_GLOBAL,
  keyRingId: secrets.JWT_SIGNER_KEY_RING_ID,
  keyId: secrets.JWT_SIGNER_KEY_ID,
  versionId: secrets.JWT_SIGNER_KEY_VERSION_ID,
});

const getAsymmKeyName = () => {
  const config = jwtSignerConfig();
  return client.cryptoKeyVersionPath(
    config.projectId,
    config.locationId,
    config.keyRingId,
    config.keyId,
    config.versionId
  );
};

const signAsymmetricRsaWithDevKey = (digestBuffer: Buffer) => {
  const sign = crypto.createSign("RSA-SHA256");
  const key = {
    key: secrets.JWT_SIGNER_DEV_PRIVATE_KEY,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  };
  sign.update(digestBuffer);
  return sign.sign(key);
};

export const signAsymmetricRsa = async (digestBuffer: Buffer) => {
  if (secrets.ENV === "dev") {
    return signAsymmetricRsaWithDevKey(digestBuffer);
  }
  const digest = crypto.createHash("sha256").update(digestBuffer).digest();
  const digestCrc32c = crc32c.calculate(digest);
  const versionName = getAsymmKeyName();
  const [signResponse] = await client.asymmetricSign({
    name: versionName,
    digest: {
      sha256: digest,
    },
    digestCrc32c: {
      value: digestCrc32c,
    },
  });

  if (signResponse.name !== versionName) {
    throw new Error("AsymmetricSign: request corrupted in-transit");
  }
  if (!signResponse.verifiedDigestCrc32c) {
    throw new Error("AsymmetricSign: request corrupted in-transit");
  }
  if (
    !signResponse.signature ||
    !signResponse.signatureCrc32c ||
    crc32c.calculate(<string>signResponse.signature) !==
      Number(signResponse.signatureCrc32c.value)
  ) {
    throw new Error("AsymmetricSign: response corrupted in-transit");
  }
  return Buffer.from(signResponse.signature);
};

export const getPublicKeyPemRsa = async () => {
  if (secrets.ENV === "dev") {
    return secrets.JWT_SIGNER_DEV_PUB_PEM;
  }
  const versionName = getAsymmKeyName();
  const [publicKey] = await client.getPublicKey({
    name: versionName,
  });
  if (!publicKey.pem) {
    throw new Error("AsymmetricVerify: public key not found");
  }
  return publicKey.pem;
};
