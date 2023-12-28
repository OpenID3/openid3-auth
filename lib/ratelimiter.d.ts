export declare function registerRateLimit(ip: string): Promise<boolean>;
export declare function checkNameRateLimit(ip: string): Promise<boolean>;
export declare function getChallengeRateLimit(ip: string): Promise<boolean>;
export declare const rateLimiter: (callName: string, rawId: string, windowInSec: number, threshold: number) => Promise<boolean>;
