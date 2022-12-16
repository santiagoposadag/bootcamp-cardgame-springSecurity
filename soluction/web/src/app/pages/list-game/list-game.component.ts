import { Component, OnDestroy, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { ApiService } from 'src/app/shared/services/api.service';
import { AuthService } from 'src/app/shared/services/auth.service';
import { WebsocketService } from 'src/app/shared/services/websocket.service';

@Component({
  selector: 'app-list-game',
  templateUrl: './list-game.component.html',
  styleUrls: ['./list-game.component.scss']
})
export class ListGameComponent implements  OnDestroy {

  juegos?: any;
  uid: string = "";

  constructor(private api: ApiService, private router: Router, private auth: AuthService, private socket: WebsocketService) {
    this.uid = JSON.parse(localStorage.getItem('user')!).uid;

    this.api.getMisJuegos(this.uid).subscribe((juegos) => {
      this.juegos = juegos;
    })

  }


  ngOnDestroy(): void {
    this.socket.close();
  }

  joinGame(id: string) {
    this.router.navigate(['board', id]);
  }
  showName(data: any){
    const alias = data.alias;
    return alias.length > 10 ? `${alias.substring(0, 10)}...` : alias;
  }

  startGame(id: string) {
    this.socket.open(id);
    this.socket.listener(
      (event) => {
        if (event.type == "cardgame.tablerocreado") {
          this.api.crearRonda({
            juegoId: id,
            tiempo: 80,
            jugadores: event.jugadorIds.map((it: any) => it.uuid)
          }).subscribe();
        }

        if (event.type == 'cardgame.rondacreada') {
          this.router.navigate(['board', id]);
        }
      }
    );
    this.api.iniciarJuego({ juegoId: id }).subscribe();
  }
}
