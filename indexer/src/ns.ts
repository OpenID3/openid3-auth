import { isAddress, getAddress } from "viem";

import { HexString, ServerError, Passkey } from "./types";
import { RedisService } from "./redis";

export const genKey = (account: string, event: string) => `${event}:${account}`;

export const NEW_OPERATORS_TOPIC_HASH = "0xeb6e48d00efa89b9649281149c3110eced61248a05e3a988265bf9dd5e50e180";
export const METADATA_TOPIC_HASH = "0xf7f858c27d9977938c4bafca84e6e31f3a77a0c886ced88da68429240ab1313e";
export const PASSKEY_TOPIC_HASH = "0x6d609710e6d70b04cc713f483dc5e373b72e140a9aa303a22c97b4a71d8658b0";

export const getOperatorsFromAddress = async (
  address: HexString
): Promise<HexString[] | undefined> => {
  if (!isAddress(address)) {
    throw new ServerError(400, "invalid address");
  }
  const normalized = getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const operators = await redis.get(
    genKey(normalized, NEW_OPERATORS_TOPIC_HASH)
  );
  if (operators) {
    const operator1 = getAddress(operators.slice(0, 42)) as HexString;
    const operator2 =  getAddress("0x" + operators.slice(42)) as HexString;
    return [operator1, operator2];
  }
};

export const getMetadataFromAddress = async (
  address: string
): Promise<string | undefined> => {
  if (!isAddress(address)) {
    throw new ServerError(400, "invalid address");
  }
  const normalized = getAddress(address) as HexString;
  const redis = await RedisService.getInstance();
  const metadata = await redis.get(genKey(normalized, METADATA_TOPIC_HASH));
  if (metadata) {
    return metadata as string;
  }
};

export const getPasskeyFromAddress = async (
  address: string
): Promise<Passkey | undefined> => {
  if (!isAddress(address)) {
    throw new ServerError(400, "invalid address");
  }
  const normalized = getAddress(address) as HexString;
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
  }
};
