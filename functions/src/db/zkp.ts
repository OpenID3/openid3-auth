import {Timestamp} from "firebase-admin/firestore";
import {Chain, JwtInput, OidcZkProof, UserOperationStruct} from "../userop";
import {firestore} from "./utils";
import {epoch} from "../utils";

export interface ZKP {
  uid: string;
  status: "processing" | "done" | "error";
  proof: OidcZkProof | null; // for done status
  error: string | null; // for error status
  chain: Chain;
  userOp: UserOperationStruct;
  jwtInput: JwtInput;
  createdAt: Timestamp;
  finishedAt: Timestamp | null;
}

export async function getZkp(uid: string): Promise<ZKP | null> {
  const result = await firestore().collection("zkp").doc(uid).get();
  if (result && result.exists) {
    return result.data() as ZKP;
  }
  return null;
}

export async function addNewZkpRequest(
    uid: string,
    jwtInput: JwtInput,
    chain: Chain,
    userOp: UserOperationStruct
) {
  await firestore()
      .collection("zkp")
      .doc(uid)
      .set({
        status: "processing",
        jwtInput,
        chain,
        userOp,
        createdAt: new Timestamp(epoch(), 0),
      });
}

export async function addZkProof(uid: string, proof: string) {
  await firestore().collection("zkp").doc(uid).update({
    status: "done",
    proof,
  });
}

export async function markZkProofError(uid: string, error: string) {
  await firestore().collection("zkp").doc(uid).update({
    status: "error",
    error,
  });
}
