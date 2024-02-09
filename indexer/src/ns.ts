import { ethers } from "ethers";
import { HexString, HexlinkError, Passkey } from "./types";
import { RedisService } from "./redis";
import { indexerIface, adminIface } from "./contract";

export const genKey = (account: string, event: string) => `${event}:${account}`;

export const NEW_OPERATORS_TOPIC_HASH =
  indexerIface.getEvent("NewOperators")!.topicHash;
export const METADATA_TOPIC_HASH =
  indexerIface.getEvent("NewMetadata")!.topicHash;
export const PASSKEY_TOPIC_HASH = adminIface.getEvent("PasskeySet")!.topicHash;

const SERVICE_URL = process.env.MIZU_BACKEND_SERVICE;

const fetchData = async (path: string) => {
  const resp = await fetch(`${SERVICE_URL}${path}`);
  const result = await resp.json();
  if (result.status === 200) {
    return JSON.parse(result.data);
  }
  if (result.status === 404) {
    return undefined;
  }
  throw new Error("Failed to fetch data");
};

const resolveName = async (name: string) => {
  const namehash = ethers.namehash(name);
  const data = await fetchData(`/info/name_to_address/${namehash.slice(2)}`);
  return data?.address;
};

export interface NostrInfo {
  nostrPubkey: string;
  relays: string[];
}

export const getNostrInfoFromName = async (
  name: string
): Promise<NostrInfo | undefined> => {
  const address = await resolveName(name);
  const account = (await fetchData(`/info/account/${address}`));
  if (account?.profile) {
    return {
      nostrPubkey: Buffer.from(account.profile.nostr_pubkey).toString("hex"),
      relays: account.profile.relays ?? [],
    };
  }
};

const getUndeployedOperators = async (
  address: HexString
): Promise<HexString[] | undefined> => {
  const data = await fetchData(`/info/registration_info/${address}`);
  return data?.operators;
};

export const getOperatorsFromName = async (
  name: string
): Promise<HexString[] | undefined> => {
  const address = await resolveName(name);
  return getOperatorsFromAddress(address);
};

export const getOperatorsFromAddress = async (
  address: HexString
): Promise<HexString[] | undefined> => {
  if (!ethers.isAddress(address)) {
    throw new HexlinkError(400, "invalid address");
  }
  const normalized = ethers.getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const operators = await redis.get(
    genKey(normalized, NEW_OPERATORS_TOPIC_HASH)
  );
  if (operators) {
    const operator1 = ethers.getAddress(operators.slice(0, 42)) as HexString;
    const operator2 =  ethers.getAddress("0x" + operators.slice(42)) as HexString;
    return [operator1, operator2];
  } else {
    return getUndeployedOperators(normalized);
  }
};

const getUndeployedMetadata = async (address: HexString): Promise<string | undefined> => {
  const data = await fetchData(`/info/registration_info/${address}`);
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
  const data = await fetchData(`/info/registration_info/${address}`);
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
    const passkey = JSON.parse(passkeyStr);
    return {
      id: passkey.id,
      pub_key: {
        x: Buffer.from(passkey.x, "hex"),
        y: Buffer.from(passkey.y, "hex"),
      }
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
