/* eslint-disable camelcase */
import { Contract, InfuraProvider, ethers } from "ethers";
import {accountFactoryIface, accountIface, adminIface} from "./contract";

export interface Passkey {
  x: string; // pubKeyX
  y: string; // pubKeyY
  id: string;
}

function formatHex(hex: string) {
  if (hex.startsWith("0x")) {
    return hex;
  }
  return "0x" + hex;
}

export function buildPasskeyAdminData(passkey: Passkey) {
  const adminData = adminIface.encodeFunctionData(
    "setPasskey",
    [
      {
        pubKeyX: BigInt(formatHex(passkey.x)),
        pubKeyY: BigInt(formatHex(passkey.y)),
      },
      passkey.id,
    ]
  );
  return ethers.solidityPacked(
    ["address", "bytes"],
    [process.env.CONTRACT_V0_0_8_PASSKEY_ADMIN!, adminData]
  );
}

export function buildAccountInitData(
  passkey: Passkey,
  operator: string,
  metadata: string
) {
  return accountIface.encodeFunctionData(
    "initialize",
    [buildPasskeyAdminData(passkey), operator, formatHex(metadata)]
  );
}

export function predictDeterministicAddressOffline(
  impl: string,
  deployer: string,
  salt: string
) {
  impl = impl.toLowerCase().slice(2);
  deployer = deployer.toLowerCase().slice(2);
  salt = salt.slice(2);
  let assembly = `3d602d80600a3d3981f3363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3ff${deployer}${salt}`;
  assembly += ethers
    .solidityPackedKeccak256(["bytes"], ["0x" + assembly.slice(0, 110)])
    .slice(2);
  return ethers.getAddress(
    ethers
      .solidityPackedKeccak256(["bytes"], ["0x" + assembly.slice(110, 280)])
      .slice(-40)
  );
}

// we have unified address across all chains so it doesn't
// matter which chain id we use
export const getProvider = (chainId = 11155111) => {
  return new InfuraProvider(chainId, process.env.INFURA_API_KEY);
};

export async function getAccountAddress(input: {
  address: string;
  factory: string;
  passkey: Passkey;
  operator: string;
  metadata: string;
}): Promise<string> {
  const provider = getProvider();
  const accountData = buildAccountInitData(
    input.passkey,
    input.operator,
    input.metadata
  );
  const salt = ethers.keccak256(accountData);
  const factory = new Contract(input.factory, accountFactoryIface, provider);
  return await factory.predictClonedAddress(salt);
}
