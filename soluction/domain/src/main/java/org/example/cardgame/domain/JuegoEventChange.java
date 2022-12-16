package org.example.cardgame.domain;

import org.example.cardgame.domain.events.*;
import org.example.cardgame.generic.EventChange;

import java.util.HashMap;
import java.util.Objects;

public class JuegoEventChange extends EventChange {
    public JuegoEventChange(Juego juego) {
        apply((JuegoCreado event) -> {
            juego.jugadores = new HashMap<>();
            juego.montoRequerido = event.getMontoRequerido();
            juego.jugadorPrincipal = event.getJugadorPrincipal();
        });
        apply((JugadorAgregado event) -> {
            juego.jugadores.put(event.getJugadorId(),
                    new Jugador(event.getJugadorId(), event.getAlias())
            );
        });

        apply((MazoAsignadoAJugador event) -> {
            if (Objects.isNull(juego.tablero)) {
                throw new IllegalArgumentException("Debe existir el tablero primero");
            }
            juego.jugadores.get(event.getJugadorId()).asignarMazo(event.getMazo());
        });

        apply((RondaCreada event) -> {
            if (Objects.isNull(juego.tablero)) {
                throw new IllegalArgumentException("Debe existir el tablero primero");
            }
            juego.ronda = event.getRonda();
            juego.tablero.ajustarTiempo(event.getTiempoLimite());
        });

        apply((TableroCreado event) -> {
            juego.tablero = new Tablero(event.getTableroId(), event.getJugadorIds());
        });

        apply((TiempoCambiadoDelTablero event) -> {
            juego.tablero.ajustarTiempo(event.getTiempoLimite());
        });

        apply((CartaPuestaEnTablero event) -> {
            if(juego.tablero.estaHabilitado().equals(Boolean.FALSE)){
                throw new IllegalArgumentException("No puedes poner la carta en el tablero");
            }
            juego.tablero.adicionarPartida(event.getJugadorId(), event.getCarta());

        });

        apply((CartaQuitadaDelTablero event) -> {
            juego.tablero.quitarCarta(event.getJugadorId(), event.getCarta());
        });

        apply((CartaQuitadaDelMazo event) -> {
            juego.jugadores.get(event.getJugadorId()).quitarCartaDeMazo(event.getCarta());
        });

        apply((RondaIniciada event) -> {
            if (Objects.isNull(juego.ronda)) {
                throw new IllegalArgumentException("Debe existir la ronda primero");
            }
            juego.ronda = juego.ronda.iniciarRonda();
            juego.tablero.habilitarApuesta();
        });

        apply((RondaTerminada event) -> {
            juego.ronda = juego.ronda.terminarRonda();
            juego.tablero.inhabilitarApuesta();
        });

        apply((CartasAsignadasAJugador event) -> {
            var jugador = juego.jugadores().get(event.getGanadorId());
            event.getCartasApuesta().forEach(jugador::agregarCartaAMazo);
        });

        apply((JuegoFinalizado event) -> {
            juego.ganador = juego.jugadores.get(event.getJugadorId());
        });

    }
}
