export interface JuegoModel {
    id:string,
    iniciado: boolean,
    jugadores: Map<string,Jugador>
}

export interface Jugador {
    alias:string,
    uid:string
}

