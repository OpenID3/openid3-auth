import SturdyWebSocket from "sturdy-websocket";
import { ethers } from "ethers";
import {
  AccountManager__factory,
  AccountManager,
  PasskeyAdmin__factory,
} from "@openid3/contracts";
import { RedisService } from "./redis";
import WebSocket from "ws";
import { LogResponse, Passkey } from "./types";

const SEPOLIA = {
  name: "sepolia",
  chainId: 11155111,
};
const SCAN_SERVICE_URL = "https://api-sepolia.etherscan.io/api";

const manager = process.env.CONTRACT_V0_0_8_ACCOUNT_MANAGER!;
const managerIface = AccountManager__factory.createInterface();
const METADATA_TOPIC_HASH = managerIface.getEvent("NewMetadata").topicHash;

const admin = process.env.CONTRACT_V0_0_8_PASSKEY_ADMIN!;
const adminIface = PasskeyAdmin__factory.createInterface();
const PASSKEY_TOPIC_HASH = adminIface.getEvent("PasskeySet").topicHash;

const provider = new ethers.InfuraProvider(
  SEPOLIA.chainId,
  process.env.INFURA_API_KEY!
);

function genUrl(query: Record<string, string>) {
  const params = new URLSearchParams(query);
  return `${SCAN_SERVICE_URL}?${params.toString()}`;
}

async function queryAllMetadataEvents(
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
    return [parsed!.args.account, parsed!.args.metadata];
  });
  await redis.mset(events);
  if (logs.length === Number(query.offset)) {
    const nextPage = Number(query.page) + 1;
    query.page = nextPage.toString();
    await queryAllMetadataEvents(query, redis);
  }
}

const subscribeMetadataEvent = async (
  wssProvider: ethers.WebSocketProvider
) => {
  const currentBlock = await provider.getBlockNumber();
  console.log("current block is ", currentBlock);
  const redis = await RedisService.getInstance();
  console.log("restoring historical events...");
  await queryAllMetadataEvents(
    {
      module: "logs",
      action: "getLogs",
      apikey: process.env.ETHERSCAN_API_KEY!,
      page: "1",
      offset: "1000",
      fromBlock: "0",
      toBlock: Number(currentBlock).toString(),
      address: manager,
      topic0: METADATA_TOPIC_HASH,
    },
    redis
  );
  console.log("all historical events restored.");
  console.log("adding listener...");
  wssProvider.on(
    {
      address: manager,
      topics: [METADATA_TOPIC_HASH],
    },
    async (log) => {
      const parsed = managerIface.parseLog(log);
      console.log(
        "NewMetadata ======> ",
        parsed!.args.account,
        " <-> ",
        parsed!.args.metadata
      );
      await redis.set(parsed!.args.account, parsed!.args.metadata);
    }
  );
};

async function queryAllPasskeySetEvent(
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
    return;
  }
  const events: Array<[string, string]> = logs.map((log) => {
    const parsed = adminIface.parseLog(log);
    const passkey = {
      x: parsed?.args.pubKey.pubKeyX,
      y: parsed?.args.pubKey.pubKeyY,
      id: parsed?.args.passkeyId,
    } as Passkey;
    console.log(
      "PasskeySet ======> ",
      parsed!.args.account,
      " <-> ",
      JSON.stringify(passkey)
    );
    return [parsed!.args.account, JSON.stringify(passkey)];
  });
  await redis.mset(events);
  if (logs.length === Number(query.offset)) {
    const nextPage = Number(query.page) + 1;
    query.page = nextPage.toString();
    await queryAllMetadataEvents(query, redis);
  }
}

export const subscribePasskeyEvent = async (
  wssProvider: ethers.WebSocketProvider
) => {
  const currentBlock = await provider.getBlockNumber();
  console.log("current block is ", currentBlock);
  const redis = await RedisService.getInstance();
  console.log("restoring historical events...");
  await queryAllPasskeySetEvent(
    {
      module: "logs",
      action: "getLogs",
      apikey: process.env.ETHERSCAN_API_KEY!,
      page: "1",
      offset: "1000",
      fromBlock: "0",
      toBlock: Number(currentBlock).toString(),
      address: admin,
      topic0: PASSKEY_TOPIC_HASH,
    },
    redis
  );
  console.log("all historical events restored.");
  console.log("adding listener...");
  wssProvider.on(
    {
      address: admin,
      topics: [PASSKEY_TOPIC_HASH],
    },
    async (log) => {
      const parsed = adminIface.parseLog(log);
      const passkey = {
        x: parsed?.args.pubKey.pubKeyX,
        y: parsed?.args.pubKey.pubKeyY,
        id: parsed?.args.passkeyId,
      } as Passkey;
      console.log(
        "PasskeySet ======> ",
        parsed!.args.account,
        " <-> ",
        JSON.stringify(passkey)
      );
      await redis.set(parsed!.args.account, JSON.stringify(passkey));
    }
  );
};

const createWebSocket = () => {
  const wssUrl = `wss://${SEPOLIA.name}.infura.io/ws/v3/${process.env.INFURA_API_KEY}`;
  return new SturdyWebSocket(wssUrl, {
    connectTimeout: 5000,
    maxReconnectAttempts: 5,
    reconnectBackoffFactor: 1.3,
    wsConstructor: WebSocket,
  });
};

const ws = createWebSocket();
const wssProvider = new ethers.WebSocketProvider(ws, SEPOLIA);

ws.onopen = async () => {
  console.log("infura ws opened");
  wssProvider.removeAllListeners();
  console.log("subscribing...");
  await Promise.all([
    subscribeMetadataEvent(wssProvider),
    subscribePasskeyEvent(wssProvider),
  ]);
};

ws.onreopen = async () => {
  console.log("infura ws reopened");
  wssProvider.removeAllListeners();
  console.log("resubscribing...");
  await Promise.all([
    subscribeMetadataEvent(wssProvider),
    subscribePasskeyEvent(wssProvider),
  ]);
};

ws.onclose = async () => {
  console.log("infura ws closed");
  wssProvider.removeAllListeners();
};
