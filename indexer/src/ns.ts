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

const buildUrl = (dev: boolean, path: string) => {
  if (dev) {
    return `https://mizu-dev-api.misfit.id/${path}`;
  } else {
    return `https://mizu-dev-api.misfit.id/${path}`;
  }
};

const fetchData = async (path: string) => {
  const url = buildUrl(process.env.ENV === "dev", path);
  const resp = await fetch(url);
  if (resp.status === 200) {
    return resp.json();
  }
  throw new Error("failed to fetch data from " + url);
};

const resolveName = async (name: string) => {
  return fetchData(`/info/name_to_address/${name}`);
};

export interface NostrInfo {
  nostrPubkey: string;
  relays: string[];
}

export const getNostrInfoFromName = async (
  name: string
): Promise<NostrInfo | undefined> => {
  const address = await resolveName(name);
  const profile = (await fetchData(`/info/profile/${address}`)) as NostrInfo;
  if (profile) {
    return {
      nostrPubkey: profile.nostrPubkey,
      relays: profile.relays,
    };
  }
};

const getUndeployedOperators = async (
  address: HexString
): Promise<HexString | undefined> => {
  const data = await fetchData(`/info/registration/${address}`);
  return data?.operators;
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
    return getUndeployedOperators(normalized);
  }
};

const getUndeployedMetadata = async (address: HexString): Promise<string | undefined> => {
  const data = await fetchData(`/info/registration/${address}`);
  return data?.metadata;
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
    return getUndeployedMetadata(normalized);
  }
};

const getUndeployedPasskey = async (address: HexString): Promise<Passkey | undefined> => {
  const data = await fetchData(`/info/registration/${address}`);
  return data?.passkey;
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
    return getUndeployedPasskey(normalized);
  }
};

export const stripHex = (value: string): string => {
  if (value.startsWith("0x")) {
    return value.slice(2);
  }
  return value;
};
