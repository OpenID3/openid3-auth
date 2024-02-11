import { RedisService } from "./redis";

const timestampKey = "timestamp";

export async function ratelimit(ip: string) {
  return await rateLimiter(`ratelimit:ip:${ip}`, 60, 30);
}

const rateLimiter = async (
  id: string,
  windowInSec: number,
  threshold: number
): Promise<boolean> => {
  const now = Date.now();
  const redis = await RedisService.getInstance();
  const snapshot = await redis.get(id);
  if (snapshot) {
    const tsMap: Map<string, number[]> = new Map(
      Object.entries(JSON.parse(snapshot))
    );

    if (!tsMap.has(timestampKey)) {
      addRecord(redis, id, [now]);
      return false;
    }

    const tsList: number[] = tsMap.get(timestampKey)!;
    const tsThre = now - 1000 * windowInSec;
    const tsInWindow = tsList.filter((ts) => ts > tsThre);
    tsInWindow.push(now);
    addRecord(redis, id, tsInWindow);

    return tsInWindow.length > threshold;
  } else {
    addRecord(redis, id, [now]);
    return false;
  }
};

const addRecord = async (
  redis: RedisService,
  id: string,
  timestampList: number[],
) => {
  const timestampMap = new Map<string, number[]>([
    [timestampKey, timestampList],
  ]);
  const timestampObj = Object.fromEntries(timestampMap);
  await redis.set(id, JSON.stringify(timestampObj));
};
