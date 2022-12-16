package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.MontoRequerido;

public class JuegoCreado extends DomainEvent {
    private final JugadorId jugadorPrincipal;
    private final MontoRequerido montoRequerido;

    public JuegoCreado(JugadorId jugadorPrincipal, MontoRequerido montoRequerido) {
        super("cardgame.juegocreado");
        this.jugadorPrincipal = jugadorPrincipal;
        this.montoRequerido = montoRequerido;
    }

    public JugadorId getJugadorPrincipal() {
        return jugadorPrincipal;
    }

    public MontoRequerido getMontoRequerido() {
        return montoRequerido;
    }
}
