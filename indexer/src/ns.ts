import { ethers } from "ethers";
import { HexString, HexlinkError, Passkey } from "./types";
import { RedisService } from "./redis";
import { indexerIface, adminIface } from "./contract";

export const genKey = (account: string, event: string) => `${event}:${account}`;

export const NEW_OPERATORS_TOPIC_HASH =
  indexerIface.getEvent("NewOperatorsSet")!.topicHash;
export const METADATA_TOPIC_HASH =
  indexerIface.getEvent("NewMetadata")!.topicHash;
export const PASSKEY_TOPIC_HASH = adminIface.getEvent("PasskeySet")!.topicHash;

function formatHex(hex: string): HexString {
  if (hex.startsWith("0x")) {
    return hex as HexString;
  } else {
    return ("0x" + hex) as HexString;
  }
}

const buildUrl = (dev: boolean) => {
  if (dev) {
    return `http://127.0.0.1:5002/v1/projects/${process.env.FIREBASE_PROJECT_ID}/databases/(default)/documents/`;
  } else {
    return `https://firestore.googleapis.com/v1/projects/${process.env.FIREBASE_PROJECT_ID}/databases/(default)/documents/`;
  }
};

const getDataFromFirestore = async (collection: string, doc: string) => {
  const urlPrefix = buildUrl(process.env.ENV === "dev");
  collection = collection + "_" + process.env.ENV;
  const resp = await fetch(`${urlPrefix}${collection}/${doc}`);
  if (resp.status === 404) {
    return undefined;
  }
  if (resp.status === 200) {
    return await resp.json();
  }
  throw new Error("Failed to fetch data from firestore");
};

const resolveName = async (name: string) => {
  const uid = ethers.namehash(name);
  const result = await getDataFromFirestore("mns", uid);
  if (result) {
    return ethers.getAddress(
      formatHex(result.fields.address.stringValue)
    ) as HexString;
  } else {
    throw new HexlinkError(404, "name not registered");
  }
};

export interface NostrInfo {
  nostrPubkey: string;
  relays: string[];
}

export const getNostrInfoFromName = async (
  name: string
): Promise<NostrInfo | undefined> => {
  const address = await resolveName(name);
  const data = await getDataFromFirestore("profiles", address);
  if (data) {
    return {
      nostrPubkey: data.fields.nostrPubkey.stringValue as string,
      relays: data.fields.relays.arrayValue.values.map(
        (v: { stringValue: string }) => v.stringValue
      ),
    };
  }
};

const getOperators = async (
  address: HexString
): Promise<HexString | undefined> => {
  const data = await getDataFromFirestore("users", address);
  if (data) {
    return data.fields.operators.stringValue as HexString;
  }
};

export const getOperatorsFromName = async (
  name: string
): Promise<HexString | undefined> => {
  const address = await resolveName(name);
  return getOperatorsFromAddress(address);
};

export const getOperatorsFromAddress = async (
  address: HexString
): Promise<HexString | undefined> => {
  if (!ethers.isAddress(address)) {
    throw new HexlinkError(400, "invalid address");
  }
  const normalized = ethers.getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const operators = await redis.get(
    genKey(normalized, NEW_OPERATORS_TOPIC_HASH)
  );
  if (operators) {
    return operators as HexString;
  } else {
    return getOperators(normalized);
  }
};

const getMetadata = async (address: HexString): Promise<string | undefined> => {
  const data = await getDataFromFirestore("users", address);
  if (data) {
    return data.fields.metadata.stringValue as string;
  }
};

export const getMetadataFromName = async (
  name: string
): Promise<string | undefined> => {
  const address = await resolveName(name);
  return getMetadataFromAddress(address);
};

export const getMetadataFromAddress = async (
  address: string
): Promise<string | undefined> => {
  if (!ethers.isAddress(address)) {
    throw new HexlinkError(400, "invalid address");
  }
  const normalized = ethers.getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const metadata = await redis.get(genKey(normalized, METADATA_TOPIC_HASH));
  if (metadata) {
    return metadata as string;
  } else {
    return getMetadata(normalized);
  }
};

const getPasskey = async (address: HexString): Promise<Passkey | undefined> => {
  const data = await getDataFromFirestore("users", address);
  if (data) {
    return {
      x: formatHex(data.fields.passkey.mapValue.fields.x.stringValue),
      y: formatHex(data.fields.passkey.mapValue.fields.y.stringValue),
      id: data.fields.passkey.mapValue.fields.id.stringValue as string,
    } as Passkey;
  }
};

export const getPasskeyFromName = async (
  name: string
): Promise<Passkey | undefined> => {
  const address = await resolveName(name);
  return getPasskeyFromAddress(address);
};

export const getPasskeyFromAddress = async (
  address: string
): Promise<Passkey | undefined> => {
  if (!ethers.isAddress(address)) {
    throw new HexlinkError(400, "invalid address");
  }
  const normalized = ethers.getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const passkeyStr = await redis.get(genKey(normalized, PASSKEY_TOPIC_HASH));
  if (passkeyStr) {
    const passkey = JSON.parse(passkeyStr) as Passkey;
    return {
      x: formatHex(passkey.x),
      y: formatHex(passkey.y),
      id: passkey.id,
    } as Passkey;
  } else {
    return getPasskey(normalized);
  }
};

export const stripHex = (value: string): string => {
  if (value.startsWith("0x")) {
    return value.slice(2);
  }
  return value;
};
