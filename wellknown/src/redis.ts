import {type RedisClientType, createClient} from "redis";

export class RedisService {
    private static instance: RedisService | null = null;
  
    private client!: RedisClientType;
  
    private constructor() {}
  
    public static async getInstance(): Promise<RedisService> {
      if (RedisService.instance == null) {
        await RedisService.initInstance();
      }
      return RedisService.instance!;
    }
  
    private static async initInstance(): Promise<void> {
      RedisService.instance = new RedisService();
      RedisService.instance.client = createClient();
      await RedisService.instance.client.connect();
    }

    public get(key: string) {
      return this.client.get(key);
    }
  
    public set(key: string, value: string) {
      return this.client.set(key, value);
    }

    public mset(values: Array<[string, string]>) {
      return this.client.mSet(values);
    }
  }