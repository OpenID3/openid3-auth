/* eslint-disable camelcase */
import {
  AccountFactory__factory,
  OpenId3Account__factory,
  PasskeyAdmin__factory,
} from "@openid3/contracts";
import * as functions from "firebase-functions";
import { Passkey } from "./db/utils";
import { InfuraProvider, ethers, getCreate2Address } from "ethers";
import { ACCOUNT_FACTORY_TO_IMPL } from "./constants";
import { RegistrationInfo } from "./db/user";
import { getServerOperator } from "./gcloudKms";
import crypto from "crypto";

const secrets = functions.config().doppler || {};

function formatHex(hex: string) {
  if (hex.startsWith("0x")) {
    return hex;
  }
  return "0x" + hex;
}

export function buildPasskeyAdminData(passkey: Passkey) {
  const adminData = PasskeyAdmin__factory.createInterface().encodeFunctionData(
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
    [secrets.CONTRACT_V0_0_8_PASSKEY_ADMIN!, adminData]
  );
}

export function buildAccountInitData(
  passkey: Passkey,
  operator: string,
  metadata: string
) {
  return OpenId3Account__factory.createInterface().encodeFunctionData(
    "initialize",
    [buildPasskeyAdminData(passkey), operator, formatHex(metadata)]
  );
}

// we have unified address across all chains so it doesn't
// matter which chain id we use
export const getProvider = (chainId = 11155111) => {
  return new InfuraProvider(chainId, secrets.INFURA_API_KEY);
};

export async function getAccountAddress(input: {
  factory: string;
  passkey: Passkey;
  operators: string;
  metadata: string;
}): Promise<string> {
  const provider = getProvider();
  const accountData = buildAccountInitData(
    input.passkey,
    input.operators,
    input.metadata
  );
  const salt = ethers.keccak256(accountData);
  const factory = AccountFactory__factory.connect(input.factory, provider);
  return await factory.predictClonedAddress(salt);
}

export function getContractAddress(registrationInfo: RegistrationInfo) {
  const initData = buildAccountInitData(
    registrationInfo.passkey,
    registrationInfo.operators,
    registrationInfo.metadata
  );
  const salt = ethers.keccak256(initData);
  const impl = ACCOUNT_FACTORY_TO_IMPL[registrationInfo.factory];
  return predictDeterministicAddress(impl, registrationInfo.factory, salt);
}

export function predictDeterministicAddress(
  impl: string,
  deployer: string,
  salt: string
) {
  return getCreate2Address(
    deployer,
    salt,
    `0x3d602d80600a3d3981f3363d3d373d3d3d363d73${impl
      .toLowerCase()
      .slice(2)}5af43d82803e903d91602b57fd5bf3ff`
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

export const genRegistrationInfo = (
  mizuname: string,
  passkey: Passkey,
  factory: string,
  operator: string
) => {
  const uid = crypto.randomBytes(32).toString("hex");
  const metadata = `${secrets.MIZU_FIREBASE_SERVICE}/getProfile/${uid}`;
  const operators = ethers.solidityPacked(
    ["address", "address"],
    [operator, getServerOperator()]
  );
  return {
    mizuname,
    passkey,
    factory,
    operators,
    metadata,
    uid,
  };
};
