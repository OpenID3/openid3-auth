import { Timestamp } from "firebase-admin/firestore";
import { Passkey, firestore } from "./utils";
import { ServerError, epoch } from "../utils";
import * as functions from "firebase-functions";

const secrets = functions.config().doppler || {};

export interface Session {
  token: string;
  issuedAt: Timestamp;
}

export interface Auth {
  passkey: Passkey;
  challenge: string | null;
  sessions: Session[];
  updatedAt: Timestamp;
}

export async function getAuth(address: string): Promise<Auth | null> {
  const result = await firestore().collection("auth").doc(address).get();
  if (result && result.exists) {
    return result.data() as Auth;
  }
  return null;
}

export async function preAuth(address: string, challenge: string) {
  await firestore()
    .collection("auth")
    .doc(address)
    .update({
      challenge: challenge,
      updatedAt: new Timestamp(epoch(), 0),
    });
}

export async function postAuth(address: string, sessions: Session[]) {
  await firestore()
    .collection("auth")
    .doc(address)
    .update({
      challenge: null,
      updatedAt: new Timestamp(epoch(), 0),
      sessions,
    });
}

export async function registerUser(
  uid: string,
  address: string,
  csrfToken: string,
  request: {
    username: string,
    passkey: Passkey,
    factory: string,
    operator: string,
    metadata: string,
    invitationCode: string,
  }
) {
  const db = firestore();
  const nsRef = db.collection("mns").doc(uid);
  const userRef = db.collection("users").doc(address);
  const authRef = db.collection("auth").doc(address);
  const skipInvitationCheck = secrets.SKIP_INVITATION_CHECK === "true";
  const codeRef = db.collection("invitations").doc(request.invitationCode);
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
      sessions: [{ token: csrfToken, issuedAt: Timestamp.now() }],
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
