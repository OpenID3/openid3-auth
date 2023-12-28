import SturdyWebSocket from "sturdy-websocket";
import { ethers } from "ethers";
import { AccountManager__factory, AccountManager } from "@openid3/contracts";
import { RedisService } from "./redis";
import WebSocket from "ws";
import { LogResponse } from "./types";

const SEPOLIA = {
  name: "sepolia",
  chainId: 11155111,
};
const manager = process.env.CONTRACT_V0_0_8_ACCOUNT_MANAGER!;
const SCAN_SERVICE_URL = "https://api-sepolia.etherscan.io/api";
const iface = AccountManager__factory.createInterface();
const TOPIC_HASH = iface.getEvent("NewMetadata").topicHash;
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
    const parsed = iface.parseLog(log);
    console.log(
      "======> ",
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

const subscribeMetadataEvent = async (wssProvider: ethers.WebSocketProvider) => {
  const currentBlock = await provider.getBlockNumber();
  console.log("current block is ", currentBlock);
  const redis = await RedisService.getInstance();
  console.log("adding listener...");
  const filter = {
    address: manager,
    topics: [TOPIC_HASH],
  };
  wssProvider.on(filter, async (log) => {
    const parsed = iface.parseLog(log);
    console.log(
      "======> ",
      parsed!.args.account,
      " <-> ",
      parsed!.args.metadata
    );
    await redis.set(parsed!.args.account, parsed!.args.metadata);
  });
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
      topic0: TOPIC_HASH,
    },
    redis
  );
  console.log("all historical events restored.");
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
  await subscribeMetadataEvent(wssProvider);
};

ws.onreopen = async () => {
  console.log("infura ws reopened");
  wssProvider.removeAllListeners();
  await subscribeMetadataEvent(wssProvider);
};

ws.onclose = async () => {
  console.log("infura ws closed");
  wssProvider.removeAllListeners();
};
