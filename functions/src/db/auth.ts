import { Timestamp } from "firebase-admin/firestore";
import { Passkey, coll, firestore } from "./utils";
import { ServerError, epoch } from "../utils";
import * as functions from "firebase-functions";

const secrets = functions.config().doppler || {};

export interface Auth {
  passkey: Passkey;
  pin: string;
  challenge: string | null;
  updatedAt: Timestamp;
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

export async function setPin(address: string, newPin: string) {
  await coll("auth").doc(address).update({
    pin: newPin,
  });
}

export async function registerUser(
  uid: string,
  address: string,
  request: {
    username: string;
    passkey: Passkey;
    factory: string;
    operator: string;
    metadata: string;
    pin: string;
    invitationCode: string;
  }
) {
  const db = firestore();
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
      pin: request.pin,
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
