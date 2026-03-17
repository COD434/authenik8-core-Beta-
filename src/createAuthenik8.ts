import {Authenik8Config} from "./types/config";
import {requireAdmin} from "./middleware/adminService";

export const createAuthenik8 =(config:Authenik8Config)=>{
return{
requireAdmin :requireAdmin(config),
}
}
