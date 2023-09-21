import {AuthenticationStrategy} from '@loopback/authentication';
import {Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';



export class BasicAuthenticationStrategy implements AuthenticationStrategy {
  name: string = 'auth';

  constructor(
  ) {}

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    console.log("ejecutando estrategia de autenticacion");
    return undefined;
  }


}
