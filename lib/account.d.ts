import { Passkey } from "./db/utils";
import { InfuraProvider } from "ethers";
export declare function buildPasskeyAdminData(passkey: Passkey): string;
export declare function buildAccountInitData(passkey: Passkey, operator: string, metadata: string): string;
export declare function predictDeterministicAddressOffline(impl: string, deployer: string, salt: string): string;
export declare const getProvider: (chainId?: number) => InfuraProvider;
export declare function getAccountAddress(input: {
    address: string;
    factory: string;
    passkey: Passkey;
    operator: string;
    metadata: string;
}): Promise<string>;
