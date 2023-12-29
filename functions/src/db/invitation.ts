import { Timestamp } from "firebase-admin/firestore";
import { firestore } from "./utils";
import { HexString } from "ethers/lib.commonjs/utils/data";

export interface Invitation {
  code: string;
  createdAt: Timestamp;
  usedBy?: HexString; // user address
  usedAt?: Timestamp;
}

export async function genInvitationCodes(num: number): Promise<string[]> {
  const db = firestore();
  const batch = db.batch();
  const codes: string[] = [];
  for (let i = 0; i < num; i++) {
    const code = crypto.randomUUID();
    codes.push(code);
    const codeRef = db.collection("invitations").doc(code);
    batch.set(codeRef, { createdAt: Timestamp.now() });
  }
  await batch.commit();
  return codes;
}
