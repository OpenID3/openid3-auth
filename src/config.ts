import * as functions from "firebase-functions";

const secrets = functions.config().doppler;

export enum KMS_KEY_TYPE {
  operator,
  encryptor,
}

export interface KMS_CONFIG_TYPE {
  projectId: string,
  locationId: string,
  keyRingId: string,
  keyId: string,
  versionId?: string,
  publicAddress?: string
}

const operatorConfig = () : KMS_CONFIG_TYPE => ({
  projectId: secrets.VITE_FIREBASE_PROJECT_ID,
  locationId: secrets.GCP_KEY_LOCATION_GLOBAL,
  keyRingId: secrets.OPERATOR_KEY_RING_ID,
  keyId: secrets.OPERATOR_KEY_ID,
  versionId: secrets.OPERATOR_VERSION_ID,
  publicAddress: secrets.OPERATOR_PUB_ADDR,
});

const encryptorConfig = () : KMS_CONFIG_TYPE => ({
  projectId: secrets.VITE_FIREBASE_PROJECT_ID,
  locationId: secrets.GCP_KEY_LOCATION_GLOBAL,
  keyRingId: secrets.ENCRYPTOR_KEY_RING_ID,
  keyId: secrets.ENCRYPTOR_KEY_ID,
});

export const kmsConfig = () => new Map<string, KMS_CONFIG_TYPE>([
  [KMS_KEY_TYPE[KMS_KEY_TYPE.operator], operatorConfig()],
  [KMS_KEY_TYPE[KMS_KEY_TYPE.encryptor], encryptorConfig()],
]);
