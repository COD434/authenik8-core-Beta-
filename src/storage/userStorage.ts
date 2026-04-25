import {UserStore} from "../types/storage"

export class Store{
constructor(private userStore:UserStore){}

async register(email:string, password:string){
const exists = await this.userStore.findByEmail(email)

if (exists){
throw new Error("If a record of user exists an email will be sent");
}

await this.userStore.create({email,password});
}

}
