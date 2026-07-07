import { UserStore } from "../types/storage";
export declare const hashPassword: (password: string) => Promise<string>;
export declare class Store {
    private readonly userStore;
    constructor(userStore: UserStore);
    register(email: string, password: string): Promise<void>;
}
//# sourceMappingURL=userStorage.d.ts.map