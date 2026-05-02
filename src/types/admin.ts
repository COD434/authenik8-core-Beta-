
import { Redis } from "ioredis";

export interface RequireAdminOptions {
  jwtSecret: string;
  redisclient?:any;
}
