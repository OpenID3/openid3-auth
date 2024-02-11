import { RedisService } from "./redis";
import {
  METADATA_TOPIC_HASH,
  PASSKEY_TOPIC_HASH,
  NEW_OPERATORS_TOPIC_HASH,
  genKey,
} from "./ns";

import { sepolia } from "viem/chains";
import { createPublicClient, http, parseEventLogs } from "viem";
import { Network } from "alchemy-sdk";
import { accountEventIndexerAbi } from "./abi/accountEventIndexerAbi";
import { passkeyAdminAbi } from "./abi/passkeyAdminAbi";
import { Log, RpcLog } from "viem";

const provider = createPublicClient({
  chain: sepolia,
  transport: http(
    `https://${Network.ETH_SEPOLIA}.g.alchemy.com/v2/${process.env.ALCHEMY_KEY}`
  ),
});

const SCAN_SERVICE_URL = "https://api-sepolia.etherscan.io/api";

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
  const logs = result.result as Log[] | RpcLog[];
  if (logs.length === 0) {
    console.log("No NewMetadata event found.");
    return;
  }
  const parsed = parseEventLogs({ abi: accountEventIndexerAbi, logs });
  const events: Array<[string, string]> = parsed.map((log) => {
    const { account, metadata } = log!.args as {
      account: string;
      metadata: string;
    };
    console.log("NewMetadata ======> ", account, " <-> ", metadata);
    return [genKey(account, METADATA_TOPIC_HASH), metadata];
  });
  await redis.mset(events);
  if (logs.length === Number(query.offset)) {
    const nextPage = Number(query.page) + 1;
    query.page = nextPage.toString();
    await indexNewMetadataEvent(query, redis);
  }
}

async function indexAllNewOperatorsEvent(
  query: Record<string, string>,
  redis: RedisService
) {
  const resp = await fetch(genUrl(query));
  const result = await resp.json();
  if (result.status === "0" && result.message !== "No records found") {
    throw new Error(result.result);
  }
  const logs = result.result as Log[] | RpcLog[];
  if (logs.length === 0) {
    console.log("No NewOperators event found.");
    return;
  }
  const parsed = parseEventLogs({ abi: accountEventIndexerAbi, logs });
  const events: Array<[string, string]> = parsed.map((log) => {
    const { account, operators } = log!.args as {
      account: string;
      operators: string;
    };
    console.log("NewOperators ======> ", account, " <-> ", operators);
    return [genKey(account, NEW_OPERATORS_TOPIC_HASH), operators];
  });
  await redis.mset(events);
  if (logs.length === Number(query.offset)) {
    const nextPage = Number(query.page) + 1;
    query.page = nextPage.toString();
    await indexAllNewOperatorsEvent(query, redis);
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
  const logs = result.result as Log[] | RpcLog[];
  if (logs.length === 0) {
    console.log("No PasskeySet event found.");
    return;
  }
  const parsed = parseEventLogs({ abi: passkeyAdminAbi, logs });
  const events: Array<[string, string]> = parsed.map((log) => {
    const passkey = JSON.stringify({
      x: log.args.pubKey.pubKeyX.toString(16),
      y: log.args.pubKey.pubKeyY.toString(16),
      id: log.args.passkeyId,
    });
    const account = log.args.account;
    console.log("PasskeySet ======> ", account, " <-> ", passkey);
    return [genKey(account, PASSKEY_TOPIC_HASH), passkey];
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
        address: process.env.CONTRACT_V0_0_9_PASSKEY_ADMIN!,
        topic0: PASSKEY_TOPIC_HASH,
      },
      redis
    ),
    indexNewMetadataEvent(
      {
        ...queryBase,
        address: process.env.CONTRACT_V0_0_9_ACCOUNT_EVENT_INDEXER!,
        topic0: METADATA_TOPIC_HASH,
      },
      redis
    ),
    indexAllNewOperatorsEvent(
      {
        ...queryBase,
        address: process.env.CONTRACT_V0_0_9_ACCOUNT_EVENT_INDEXER!,
        topic0: NEW_OPERATORS_TOPIC_HASH,
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

indexEventsNoThrow();

// run every 30s
// setInterval(indexEventsNoThrow, 30000);
