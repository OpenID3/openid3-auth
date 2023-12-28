import { firestore } from "./utils";

export interface NameData {
  address: string;
}

export async function resolveName(uid: string) {
  const name = await firestore().collection("mns").doc(uid).get();
  if (name && name.exists) {
    return (name.data() as NameData).address;
  }
  return null;
}
