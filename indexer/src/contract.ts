import { ethers } from "ethers";
import { accountEventIndexerAbi } from "./abi/accountEventIndexerAbi";
import { passkeyAdminAbi } from "./abi/passkeyAdminAbi";
import { openid3AccountAbi } from "./abi/openid3AccountAbi";
import { accountFactoryAbi } from "./abi/accountFactoryAbi";

export const indexer = process.env.CONTRACT_V0_0_9_ACCOUNT_EVENT_INDEXER!;
export const indexerIface = new ethers.Interface(accountEventIndexerAbi);

export const admin = process.env.CONTRACT_V0_0_9_PASSKEY_ADMIN!;
export const adminIface = new ethers.Interface(passkeyAdminAbi);

export const accountIface = new ethers.Interface(openid3AccountAbi);

export const factory = process.env.CONTRACT_V0_0_9_ACCOUNT_FACTORY!;
export const accountFactoryIface = new ethers.Interface(accountFactoryAbi);