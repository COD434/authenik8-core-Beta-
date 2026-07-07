export interface User {
    id: string;
    email: string;
    passwordHash?: string;
    role?: string;
    type?: string;
}
export interface UserStore {
    findByEmail(email: string): Promise<User | null>;
    findById(id: string): Promise<User | null>;
    create(user: Partial<User>): Promise<User>;
    update(id: string, data: Partial<User>): Promise<User>;
}
//# sourceMappingURL=storage.d.ts.map