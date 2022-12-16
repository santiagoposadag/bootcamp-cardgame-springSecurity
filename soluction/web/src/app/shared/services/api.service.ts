import {HttpClient} from '@angular/common/http';
import {Injectable} from '@angular/core';
import {AngularFirestore} from '@angular/fire/compat/firestore';
import {Observable} from 'rxjs';
import {map} from 'rxjs/operators';
import {environment} from 'src/environments/environment';
import {CrearJuegoCommand} from '../commands/crearJuegoCommand';
import {CrearRondaCommand} from '../commands/crearRondaCommand';
import {IniciarJuegoCommand} from '../commands/iniciarJuegoCommand';
import {IniciarRondaCommand} from '../commands/iniciarRondaCommand';
import {PonerCartaEnTableroCommand} from '../commands/ponerCartaEnTableroCommand';
import {JuegoModel, Jugador} from '../model/juego';
import {TableroModel} from '../model/tablero';
import {User} from '../model/user';

@Injectable({
  providedIn: 'root'
})
export class ApiService {


  constructor(private http: HttpClient, public afs: AngularFirestore,
  ) { }

  crearJuego(command: CrearJuegoCommand) {
    return this.http.post(environment.apiBaseCommand + '/juego/crear', command);
  }

  iniciarJuego(command: IniciarJuegoCommand){
    return this.http.post(environment.apiBaseCommand + '/juego/iniciar', command);
  }

  crearRonda(command: CrearRondaCommand){
    return this.http.post(environment.apiBaseCommand + '/juego/crear/ronda', command);
  }

  iniciarRonda(command: IniciarRondaCommand){
    return this.http.post(environment.apiBaseCommand + '/juego/ronda/iniciar', command);
  }

  ponerCarta(command: PonerCartaEnTableroCommand){
    return this.http.post(environment.apiBaseCommand + '/juego/poner', command);
  }

  getJugadores(): Observable<Jugador[]> {
    return this.afs.collection<User>(`users`).snapshotChanges().pipe(map((actions) => {
      return actions.map(item => {
        const data = item.payload.doc.data();
        return {uid: data.uid, alias: data.displayName};
      });
    }));
  }

  getMisJuegos(uid: string): Observable<JuegoModel[]> {
    return this.http.get<JuegoModel[]>(environment.apiBaseQuery + '/juego/listar/' + uid);
   }

  getMiMazo(uid: string, juegoId: string) {
    return this.http.get(environment.apiBaseQuery + '/juego/mazo/' + juegoId + '/' + uid);
  }

  getTablero(juegoId: string): Observable<TableroModel> {
    return this.http.get<TableroModel>(environment.apiBaseQuery + '/juego/' + juegoId);
  }
}
