import { Timestamp } from "firebase-admin/firestore";
import { Passkey, coll, firestore } from "./utils";
import * as functions from "firebase-functions";
import { ServerError, epoch } from "../utils";

const secrets = functions.config().doppler || {};

export interface User {
  uid: string;
  registrationInfo: RegistrationInfo;
  profile: UserProfile;
  auth: Auth;
  createdAt: Timestamp;
}

export interface Auth {
  passkey: Passkey;
  nonce: number | null;
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

export async function postAuth(address: string) {
  await coll("auth")
    .doc(address)
    .update({
      challenge: null,
      updatedAt: new Timestamp(epoch(), 0),
    });
}

export async function registerUser(
  uid: string,
  address: string,
  request: {
    mizuname: string;
    passkey: Passkey;
    factory: string;
    operator: string;
    profile: UserProfile;
    pin: string;
    invitationCode: string;
  }
) {
  const db = firestore();
  const registrationInfo = {
    mizuname,
    passkey,
    factory,
    operator,
    metadata,
  };
  const nsRef = coll("mns").doc(uid);
  const userRef = coll("users").doc(address);
  const authRef = coll("auth").doc(address);
  const skipInvitationCheck = secrets.SKIP_INVITATION_CHECK === "true";
  const codeRef = coll("invitations").doc(request.invitationCode);
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
      passkey: request.passkey,
      factory: request.factory,
      operator: request.operator,
      metadata: request.metadata,
      username: request.username,
      createdAt: Timestamp.now(),
    });
    t.set(authRef, {
      passkey: request.passkey,
      pin: "",
      updatedAt: Timestamp.now(),
    });
    if (!skipInvitationCheck) {
      t.update(codeRef, {
        usedBy: address,
        usedAt: Timestamp.now(),
      });
    }
  });
}
