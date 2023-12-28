export interface NameData {
    address: string;
}
export declare function resolveName(uid: string): Promise<string | null>;
