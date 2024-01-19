import { ethers } from "ethers";
import { HexString, HexlinkError, Passkey } from "./types";
import { genNameHash } from "./name";
import { RedisService } from "./redis";
import {
  AccountManager__factory,
  PasskeyAdmin__factory,
} from "@openid3/contracts";
import { coll } from "./firebase";

export const genKey = (account: string, event: string) => `${event}:${account}`;

export const METADATA_TOPIC_HASH =
  AccountManager__factory.createInterface().getEvent("NewMetadata").topicHash;
export const PASSKEY_TOPIC_HASH =
  PasskeyAdmin__factory.createInterface().getEvent("PasskeySet").topicHash;

function formatHex(hex: string): HexString {
  if (hex.startsWith("0x")) {
    return hex as HexString;
  } else {
    return ("0x" + hex) as HexString;
  }
}

const resolveUid = async (uid: string) => {
  const result = await coll("mns").doc(uid).get();
  if (result && result.exists) {
    const mns = result.data() as {address: string};
    return ethers.getAddress(mns.address);
  }
};

const getMetadata = async (
  address: HexString
): Promise<HexString | undefined> => {
  const result = await coll("users").doc(address).get()
  if (result && result.exists) {
    const user = result.data() as {metadata: string};
    return formatHex(user.metadata);
  }
};

const getPasskey = async (
  address: HexString
): Promise<Passkey | undefined> => {
  const result = await coll("users").doc(address).get();
  if (result && result.exists) {
    const user = result.data() as {passkey: Passkey};
    return {
      x: formatHex(user.passkey.x),
      y: formatHex(user.passkey.y),
      id: user.passkey.id,
    }
  }
};

export const getPubkeyFromName = async (
  name: string
): Promise<HexString | undefined> => {
  const uid = genNameHash(name);
  const address = await resolveUid(uid);
  if (!address) {
    throw new HexlinkError(404, "name not registered");
  }
  return getPubkeyFromAddress(address);
};

export const getPubkeyFromAddress = async (
  address: string
): Promise<HexString | undefined> => {
  if (!ethers.isAddress(address)) {
    throw new HexlinkError(400, "invalid address");
  }
  const normalized = ethers.getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const pubkey = await redis.get(genKey(normalized, METADATA_TOPIC_HASH));
  if (pubkey) {
    return pubkey as HexString;
  } else {
    return getMetadata(normalized);
  }
};

export const getPasskeyFromName = async (
  name: string
): Promise<Passkey | undefined> => {
  const uid = genNameHash(name);
  const address = await resolveUid(uid);
  if (!address) {
    throw new HexlinkError(404, "name not registered");
  }
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
