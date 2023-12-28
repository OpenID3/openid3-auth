import { Timestamp } from "firebase-admin/firestore";
import { Chain, JwtInput, OidcZkProof, UserOperationStruct } from "../userop";
export interface ZKP {
    uid: string;
    status: "processing" | "done" | "error";
    proof: OidcZkProof | null;
    error: string | null;
    chain: Chain;
    userOp: UserOperationStruct;
    jwtInput: JwtInput;
    createdAt: Timestamp;
    finishedAt: Timestamp | null;
}
export declare function getZkp(uid: string): Promise<ZKP | null>;
export declare function addNewZkpRequest(uid: string, jwtInput: JwtInput, chain: Chain, userOp: UserOperationStruct): Promise<void>;
export declare function addZkProof(uid: string, proof: string): Promise<void>;
export declare function markZkProofError(uid: string, error: string): Promise<void>;
