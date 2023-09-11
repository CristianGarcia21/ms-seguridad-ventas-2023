import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import {Credenciales, Usuario} from '../models';
import {repository} from '@loopback/repository';
import {UsuarioRepository} from '../repositories';
const  generator = require('generate-password');
const MD5 = require("crypto-js/md5");

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario : UsuarioRepository
  ) {}

  /**
   * Crear una clave aleatoria
   * @returns cadena aleatoria de  n caracteres
   */
  crearTextoAleatorio(n:number):string{
    let clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave;
  }

  /**
   *cifrar una  cadena con metodo MD5
   * @param cadena texto a cifrar
   * @returns cadena cifrada con MD5
   */
  cifrarTexto(cadena:string){
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   *Se busca un usuario por sus credenciales de acceso
   * @param credenciales credenciales del usuario
   * @returns usuario encontrado o null
   */
  async identificarUsuario(credenciales:Credenciales): Promise<Usuario|null>{
    let usuario = await this.repositorioUsuario.findOne({
      where:{
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    });
    return usuario as Usuario
  }
}
