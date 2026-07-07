import { randomBytes, scrypt as scryptCallback } from "crypto";
import { promisify } from "util";
import { UserStore } from "../types/storage";

const scrypt = promisify(scryptCallback);
const PASSWORD_KEY_LENGTH = 64;

export const hashPassword = async (password: string): Promise<string> => {
  const salt = randomBytes(16).toString("hex");
  const derivedKey = (await scrypt(
    password,
    salt,
    PASSWORD_KEY_LENGTH
  )) as Buffer;

  return `scrypt$${salt}$${derivedKey.toString("hex")}`;
};

export class Store {
  constructor(private readonly userStore: UserStore) {}

  async register(email: string, password: string): Promise<void> {
    const exists = await this.userStore.findByEmail(email);

    if (exists) {
      throw new Error("If a record of user exists an email will be sent");
    }

    const passwordHash = await hashPassword(password);
    await this.userStore.create({ email, passwordHash });
  }
}
