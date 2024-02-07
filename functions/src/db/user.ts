import { Timestamp } from "firebase-admin/firestore";
import { Passkey, coll } from "./utils";

// use address as key for user
export interface User {
  passkey: Passkey;
  factory: string; // factory address
  operator: string; // operator address
  metadata: string; // metadata for user
  username: string; // mizu name of user
  createdAt: Timestamp;
}

export interface UserProfile {
  name?: string;
  about?: string;
  avatar?: string;
  relays: string[];
  nostrPubkey: string;
  mizuname: string;
}

export async function getUser(address: string): Promise<User | null> {
  const result = await coll("users").doc(address).get();
  if (result && result.exists) {
    return result.data() as User;
  }
  return null;
}

export async function userExist(address: string): Promise<boolean> {
  const result = await coll("users").doc(address).get();
  if (result && result.exists) {
    return true;
  }
  return false;
}

export async function getProfile(address: string): Promise<UserProfile | null> {
  const result = await coll("profiles").doc(address).get();
  if (result && result.exists) {
    return result.data() as UserProfile;
  }
  return null;
}

export async function updateProfile(
  address: string,
  profile: UserProfile
): Promise<void> {
  await coll("profiles").doc(address).update(address, profile);
}
