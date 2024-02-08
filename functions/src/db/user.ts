import { Timestamp } from "firebase-admin/firestore";
import { Passkey, coll, firestore } from "./utils";
import * as functions from "firebase-functions";
import { ServerError, epoch } from "../utils";


const secrets = functions.config().doppler || {};

export interface User {
  passkey: Passkey;
  nonce: number;
  registrationInfo: RegistrationInfo;
  profile: UserProfile;
  createdAt: Timestamp;
}

// use address as key for user
export interface RegistrationInfo {
  factory: string; // factory address
  passkey: Passkey;
  operators: string; // operator address
  metadata: string; // metadata for user
  mizuname: string;
  uid: string; // user id
}

export interface UserProfile {
  name?: string;
  about?: string;
  avatar?: string;
  relays: string[];
  nostrPubkey: string;
  mizuname: string;
}

export async function getRegistrationInfo(
  address: string
): Promise<RegistrationInfo | null> {
  const result = await coll("users").doc(address).get();
  if (result && result.exists) {
    const user = result.data() as User;
    return user.registrationInfo;
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
  const result = await coll("users").doc(address).get();
  if (result && result.exists) {
    return result.data() as UserProfile;
  }
  return null;
}

export async function updateProfile(
  address: string,
  profile: UserProfile
): Promise<void> {
  await coll("users").doc(address).update(address, { profile });
}

export async function getAuth(address: string): Promise<Auth | null> {
  const result = await coll("auth").doc(address).get();
  if (result && result.exists) {
    return result.data() as Auth;
  }
  return null;
}

export async function preAuth(address: string, challenge: string) {
  await coll("auth")
    .doc(address)
    .update({
      challenge: challenge,
      updatedAt: new Timestamp(epoch(), 0),
    });
}

export async function postAuth(address: string, nonce: number) {
  await coll("auth")
    .doc(address)
    .update({nonce: nonce + 1});
}

export async function registerUser(
  address: string,
  nameHash: string,
  passkey: Passkey,
  registrationInfo: RegistrationInfo,
  profile: UserProfile,
  invitationCode: string,
) {
  const db = firestore();
  const nsRef = coll("mns").doc(nameHash);
  const userRef = coll("users").doc(address);
  const skipInvitationCheck = secrets.SKIP_INVITATION_CHECK === "true";
  const codeRef = coll("invitations").doc(invitationCode);
  await db.runTransaction(async (t) => {
    const user = await t.get(nsRef);
    if (user && user.exists) {
      throw new ServerError(400, "name already taken");
    }
    if (!skipInvitationCheck) {
      const invitation = await t.get(codeRef);
      if (invitation && invitation.exists) {
        if (invitation.data()?.usedBy) {
          throw new ServerError(400, "invitation code already used");
        }
      } else {
        throw new ServerError(400, "invalid invitation code");
      }
    }
    t.set(nsRef, { address });
    t.set(userRef, {
      passkey,
      nonce: 0,
      registrationInfo,
      profile,
      createdAt: Timestamp.now(),
    });
    if (!skipInvitationCheck) {
      t.update(codeRef, {
        usedBy: address,
        usedAt: Timestamp.now(),
      });
    }
  });
}
