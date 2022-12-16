package org.example.cardgame.domain;


import org.example.cardgame.domain.events.*;
import org.example.cardgame.domain.values.*;
import org.example.cardgame.generic.AggregateRoot;
import org.example.cardgame.generic.DomainEvent;

import java.util.List;
import java.util.Map;
import java.util.Set;

public class Juego extends AggregateRoot<JuegoId> {
    protected Map<JugadorId, Jugador> jugadores;
    protected Tablero tablero;
    protected Jugador ganador;
    protected Ronda ronda;
    protected JugadorId jugadorPrincipal;
    protected MontoRequerido montoRequerido;

    public Juego(JuegoId id, JugadorId uid, MontoRequerido montoRequerido) {
        super(id);
        subscribe(new JuegoEventChange(this));
        appendChange(new JuegoCreado(uid, montoRequerido)).apply();
    }

    private Juego(JuegoId id) {
        super(id);
        subscribe(new JuegoEventChange(this));
    }

    public static Juego from(JuegoId juegoId, List<DomainEvent> events) {
        var juego = new Juego(juegoId);
        events.forEach(juego::applyEvent);
        return juego;
    }

    public void crearTablero() {
        appendChange(new TableroCreado(new TableroId(), jugadores().keySet())).apply();
    }

    public void crearRonda(Ronda ronda, TiempoLimite tiempo) {
        appendChange(new RondaCreada(ronda, tiempo)).apply();
    }

    public void cambiarTiempoDelTablero(TableroId tableroId, TiempoLimite tiempoLimite) {
        appendChange(new TiempoCambiadoDelTablero(tableroId, tiempoLimite)).apply();

        if(tiempoLimite.value() == 1){
            appendChange(new CuentaRegresivaFinalizada()).apply();
        }

    }

    public void ponerCartaEnTablero(TableroId tableroId, JugadorId jugadorId, Carta carta) {
        appendChange(new CartaPuestaEnTablero(tableroId, jugadorId, carta)).apply();
        appendChange(new CartaQuitadaDelMazo(jugadorId, carta)).apply();
    }

    public void quitarCartaEnTablero(TableroId tableroId, JugadorId jugadorId, Carta carta) {
        appendChange(new CartaQuitadaDelTablero(tableroId, jugadorId, carta)).apply();
    }

    public void asignarJugador(JugadorId jugadorId, Alias alias){
        appendChange(new JugadorAgregado(jugadorId, alias)).apply();
    }

    public void asignarMazoAJugador(JugadorId jugadorId, Mazo mazo){
        appendChange(new MazoAsignadoAJugador(jugadorId, mazo)).apply();
    }

    public void iniciarRonda() {
        appendChange(new RondaIniciada()).apply();
    }


    public void devolverCartasAlGanador(JugadorId ganadorId, Integer puntos, Set<Carta> cartasApuesta) {
        appendChange(new CartasAsignadasAJugador(ganadorId, puntos, cartasApuesta)).apply();
    }

    public void terminarRonda(TableroId tableroId, Set<JugadorId> jugadorIds) {
        appendChange(new RondaTerminada(tableroId, jugadorIds)).apply();
    }

    public void finalizarJuego(JugadorId jugadorId, Alias alias) {
        appendChange(new JuegoFinalizado(jugadorId, alias)).apply();
    }

    public Ronda ronda() {
        return ronda;
    }

    public Tablero tablero() {
        return tablero;
    }

    public Carta obtenerCartaDelMazoDelJugador(JugadorId jugadorId, CartaMaestraId cartaMaestraId){
        var cartas = jugadores().get(jugadorId).mazo().value().cartas();
        return cartas
                .stream()
                .filter(c -> c.value().cartaId().equals(cartaMaestraId))
                .findFirst()
                .orElseThrow();
    }
    public Map<JugadorId, Jugador> jugadores() {
        return jugadores;
    }

    public Jugador ganador() {
        return ganador;
    }

    public MontoRequerido montoRequerido() {
        return montoRequerido;
    }
}
