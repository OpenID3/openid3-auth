import {Timestamp} from "firebase-admin/firestore";
import {Passkey, firestore} from "./utils";

// use address as key for user
export interface User {
  passkey: Passkey;
  operator: string; // operator address
  metadata: string; // metadata for user
  name?: string;
  createdAt: Timestamp;
}

export async function getUser(address: string): Promise<User | null> {
  const result = await firestore().collection("users").doc(address).get();
  if (result && result.exists) {
    return result.data() as User;
  }
  return null;
}

export async function userExist(address: string): Promise<boolean> {
  const result = await firestore().collection("users").doc(address).get();
  if (result && result.exists) {
    return true;
  }
  return false;
}
