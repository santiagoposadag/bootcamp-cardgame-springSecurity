export interface TableroModel {
    id:string,
    ronda: Ronda,
    tiempo: number,
    tablero: Tablero
}

export interface Tablero {
    id:string,
    habilitado: boolean,
    jugadores: [],
    cartas: Map<string, Map<string, Carta>>
}
export interface Ronda {
    jugadores: [],
    numero: number,
    estaIniciada: boolean
}

export interface Carta {
    cartaId:string,
    estaOculta:boolean,
    poder:number,
    estaHabilitada:boolean
}

