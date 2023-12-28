import * as admin from "firebase-admin";

const txServiceRateDBRef = "functions/rates/";
const timestampKey = "timestamp";

export async function registerRateLimit(ip: string) {
  return await rateLimiter("sign_up", `ip_${ip}`, 60, 10);
}

export async function checkNameRateLimit(ip: string) {
  return await rateLimiter("check_name", `ip_${ip}`, 60, 30);
}

export async function getChallengeRateLimit(ip: string) {
  return await rateLimiter("get_challenge", `ip_${ip}`, 60, 30);
}

export const rateLimiter = async (
  callName: string,
  rawId: string,
  windowInSec: number,
  threshold: number
): Promise<boolean> => {
  const callRef = txServiceRateDBRef + callName;
  const ref = admin.database().ref(callRef);
  const id = rawId.replace(/\/|\.|#|$/g, ":");

  const now = Date.now();
  const snapshot = await ref.child(`${id}`).get();
  if (snapshot.exists()) {
    const snapVal: string = snapshot.val();
    const tsMap: Map<string, number[]> = new Map(
      Object.entries(JSON.parse(snapVal))
    );

    if (!tsMap.has(timestampKey)) {
      addRecord(id, [now], ref);
      return false;
    }

    const tsList: number[] = tsMap.get(timestampKey)!;
    const tsThre = now - 1000 * windowInSec;
    const tsInWindow = tsList.filter((ts) => ts > tsThre);
    tsInWindow.push(now);
    addRecord(id, tsInWindow, ref);

    return tsInWindow.length > threshold;
  } else {
    addRecord(id, [now], ref);
    return false;
  }
};

const addRecord = (
  id: string,
  timestampList: number[],
  ref: admin.database.Reference
) => {
  const timestampMap = new Map<string, number[]>([
    [timestampKey, timestampList],
  ]);
  const timestampObj = Object.fromEntries(timestampMap);
  ref.update({ [`${id}`]: JSON.stringify(timestampObj) });
};
