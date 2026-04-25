import { TokenPayload } from "../types/tokens";
declare global {
    namespace Express {
        interface Request {
            user?: TokenPayload;
        }
    }
}
//# sourceMappingURL=oauth1.test.d.ts.map