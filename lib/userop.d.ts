import { AddressLike, BigNumberish, BytesLike } from "ethers";
import { StaticJsonRpcProvider } from "@ethersproject/providers";
import { GoogleZkAdmin } from "@openid3/contracts";
export type UserOperationStruct = {
    sender: AddressLike;
    nonce: BigNumberish;
    initCode: BytesLike;
    callData: BytesLike;
    callGasLimit: BigNumberish;
    verificationGasLimit: BigNumberish;
    preVerificationGas: BigNumberish;
    maxFeePerGas: BigNumberish;
    maxPriorityFeePerGas: BigNumberish;
    paymasterAndData: BytesLike;
    signature: BytesLike;
};
export interface JwtInput {
    kidSha256: string;
    iat: string;
    jwtHeaderAndPayloadHash: string;
    jwtSignature: string;
}
export interface OidcZkProof {
    input_hash: string;
    output_hash: string;
    verifier_digest: string;
    proof: string;
}
export interface Chain {
    name: string;
    id: number;
}
export declare const getPimlicoBundler: (chain: Chain) => StaticJsonRpcProvider;
export declare const genUserOpHash: (chain: Chain, op: UserOperationStruct) => Promise<string>;
export declare function submitUserOp(chain: Chain, op: UserOperationStruct): Promise<any>;
export declare const buildZkAdminData: (admin: GoogleZkAdmin, accountHash: string) => string;
export declare function genZkAdminSignature(jwt: JwtInput, proof: OidcZkProof): string;
