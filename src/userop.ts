import {AddressLike, BigNumberish, BytesLike, ethers} from "ethers";
import {StaticJsonRpcProvider} from "@ethersproject/providers";
import {deepHexlify} from "@account-abstraction/utils";
import {GoogleZkAdmin} from "@openid3/contracts";

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
  kidSha256: string,
  iat: string,
  jwtHeaderAndPayloadHash: string,
  jwtSignature: string,
}

export interface OidcZkProof {
  input_hash: string;
  output_hash: string;
  verifier_digest: string;
  proof: string;
}

const ENTRY_POINT_ADDRESS = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";

export interface Chain {
  name: string;
  id: number;
}

export const getPimlicoBundler = (chain: Chain) => {
  const apiKey = process.env.PIMLICO_API_KEY;
  return new StaticJsonRpcProvider(
      `https://api.pimlico.io/v1/${chain.name}/rpc?apikey=${apiKey}`
  );
};

export const genUserOpHash = async (
    chain: Chain,
    op: UserOperationStruct
) => {
  const opHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
          [
            "address",
            "uint256",
            "bytes32",
            "bytes32",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "bytes32",
          ],
          [
            op.sender,
            op.nonce,
            ethers.keccak256(op.initCode),
            ethers.keccak256(op.callData),
            op.callGasLimit,
            op.verificationGasLimit,
            op.preVerificationGas,
            op.maxFeePerGas,
            op.maxPriorityFeePerGas,
            ethers.keccak256(op.paymasterAndData),
          ]
      )
  );
  return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
          ["bytes32", "address", "uint256"],
          [opHash, ENTRY_POINT_ADDRESS, chain.id]
      )
  );
};

export async function submitUserOp(chain: Chain, op: UserOperationStruct) {
  const bundler = getPimlicoBundler(chain);
  const hexifiedUserOp = deepHexlify(await ethers.resolveProperties(op));
  const uoHash = await bundler.send("eth_sendUserOperation", [
    hexifiedUserOp,
    ENTRY_POINT_ADDRESS,
  ]);
  return uoHash;
}

export const buildZkAdminData = (
    admin: GoogleZkAdmin,
    accountHash: string,
) => {
  const adminData = admin.interface.encodeFunctionData(
      "linkAccount", [accountHash]
  );
  return ethers.solidityPacked(
      ["address", "bytes"], [admin.target, adminData]);
};

export function genZkAdminSignature(
    jwt: JwtInput,
    proof: OidcZkProof,
): string {
  const validationData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["tuple(tuple(bytes32, string, bytes32, bytes), bytes32, bytes)"],
      [
        [
          [
            jwt.kidSha256,
            jwt.iat,
            jwt.jwtHeaderAndPayloadHash,
            jwt.jwtSignature,
          ],
          proof.verifier_digest,
          proof.proof,
        ],
      ]
  );
  return ethers.solidityPacked(
      ["uint8", "bytes"], [1, validationData]);
}
