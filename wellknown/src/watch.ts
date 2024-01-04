import { ethers } from "ethers";
import {
  AccountManager__factory,
  PasskeyAdmin__factory,
} from "@openid3/contracts";
import { RedisService } from "./redis";
import { LogResponse, Passkey } from "./types";
import { METADATA_TOPIC_HASH, PASSKEY_TOPIC_HASH, genKey } from "./ns";

const SEPOLIA = {
  name: "sepolia",
  chainId: 11155111,
};
const SCAN_SERVICE_URL = "https://api-sepolia.etherscan.io/api";

const manager = process.env.CONTRACT_V0_0_8_ACCOUNT_MANAGER!;
const managerIface = AccountManager__factory.createInterface();

const admin = process.env.CONTRACT_V0_0_8_PASSKEY_ADMIN!;
const adminIface = PasskeyAdmin__factory.createInterface();

const provider = new ethers.InfuraProvider(
  SEPOLIA.chainId,
  process.env.INFURA_API_KEY!
);

function genUrl(query: Record<string, string>) {
  const params = new URLSearchParams(query);
  return `${SCAN_SERVICE_URL}?${params.toString()}`;
}

async function indexNewMetadataEvent(
  query: Record<string, string>,
  redis: RedisService
) {
  const resp = await fetch(genUrl(query));
  const result = await resp.json();
  if (result.status === "0" && result.message !== "No records found") {
    throw new Error(result.result);
  }
  const logs = result.result as LogResponse[];
  if (logs.length === 0) {
    console.log("No NewMetadata event found.");
    return;
  }
  const events: Array<[string, string]> = logs.map((log) => {
    const parsed = managerIface.parseLog(log);
    console.log(
      "NewMetadata ======> ",
      parsed!.args.account,
      " <-> ",
      parsed!.args.metadata
    );
    return [
      genKey(parsed!.args.account, METADATA_TOPIC_HASH),
      parsed!.args.metadata,
    ];
  });
  await redis.mset(events);
  if (logs.length === Number(query.offset)) {
    const nextPage = Number(query.page) + 1;
    query.page = nextPage.toString();
    await indexNewMetadataEvent(query, redis);
  }
}

async function indexAllPasskeySetEvent(
  query: Record<string, string>,
  redis: RedisService
) {
  const resp = await fetch(genUrl(query));
  const result = await resp.json();
  if (result.status === "0" && result.message !== "No records found") {
    throw new Error(result.result);
  }
  const logs = result.result as LogResponse[];
  if (logs.length === 0) {
    console.log("No PasskeySet event found.");
    return;
  }
  const events: Array<[string, string]> = logs.map((log) => {
    const parsed = adminIface.parseLog(log);
    const passkey = {
      x: parsed?.args.pubKey.pubKeyX.toString(16),
      y: parsed?.args.pubKey.pubKeyY.toString(16),
      id: parsed?.args.passkeyId,
    } as Passkey;
    console.log(
      "PasskeySet ======> ",
      parsed!.args.account,
      " <-> ",
      JSON.stringify(passkey)
    );
    return [
      genKey(parsed!.args.account, PASSKEY_TOPIC_HASH),
      JSON.stringify(passkey),
    ];
  });
  await redis.mset(events);
  if (logs.length === Number(query.offset)) {
    const nextPage = Number(query.page) + 1;
    query.page = nextPage.toString();
    await indexAllPasskeySetEvent(query, redis);
  }
}

const indexEvents = async () => {
  const redis = await RedisService.getInstance();
  const fromBlock = (await redis.get("lastBlock")) ?? "0";
  const toBlock = (await provider.getBlockNumber()).toString();
  if (Number(fromBlock) >= Number(toBlock)) {
    return;
  }
  console.log("Indexing from block ", fromBlock, " to block ", toBlock);
  const queryBase = {
    module: "logs",
    action: "getLogs",
    apikey: process.env.ETHERSCAN_API_KEY!,
    page: "1",
    offset: "1000",
    fromBlock,
    toBlock,
  };
  await Promise.all([
    indexAllPasskeySetEvent(
      {
        ...queryBase,
        address: admin,
        topic0: PASSKEY_TOPIC_HASH,
      },
      redis
    ),
    indexNewMetadataEvent(
      {
        ...queryBase,
        address: manager,
        topic0: METADATA_TOPIC_HASH,
      },
      redis
    ),
  ]);
  await redis.set("lastBlock", toBlock);
};

const indexEventsNoThrow = async () => {
  try {
    await indexEvents();
  } catch (err) {
    console.log("failed to index events: ", err);
  }
};

// run every 30s
setInterval(indexEventsNoThrow, 30000);
