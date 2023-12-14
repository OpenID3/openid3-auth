/* eslint-disable camelcase */
import {
  OpenId3Account__factory,
  PasskeyAdmin__factory,
} from "@openid3/contracts";
import * as functions from "firebase-functions";
import {Passkey} from "./db";
import {ethers} from "ethers";

const secrets = functions.config().doppler || {};

function formatHex(hex: string) {
  if (hex.startsWith("0x")) {
    return hex;
  }
  return "0x" + hex;
}

export function buildPasskeyAdminData(passkey: Passkey) {
  const admin = new ethers.Interface(PasskeyAdmin__factory.abi);
  const adminData = admin.encodeFunctionData("setPasskey", [
    {
      pubKeyX: BigInt(formatHex(passkey.x)),
      pubKeyY: BigInt(formatHex(passkey.y)),
    },
    passkey.id,
  ]);
  return ethers.solidityPacked(
      ["address", "bytes"],
      [secrets.CONTRACT_V0_0_8_PASSSKEY_ADMIN!, adminData]
  );
}

export function buildAccountInitData(
    passkey: Passkey,
    operator: string,
    metadata: string
) {
  const account = new ethers.Interface(OpenId3Account__factory.abi);
  return account.encodeFunctionData("initialize", [
    buildPasskeyAdminData(passkey),
    operator,
    formatHex(metadata),
  ]);
}

function predictDeterministicAddress(
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

export function getAccountAddress(
    passkey: Passkey,
    operator: string,
    metadata: string
) {
  const accountData = buildAccountInitData(passkey, operator, metadata);
  return predictDeterministicAddress(
    secrets.CONTRACT_V0_0_8_ACCOUNT_PROXY!,
    secrets.CONTRACT_V0_0_8_ACCOUNT_FACTORY!,
    ethers.keccak256(accountData)
  );
}
