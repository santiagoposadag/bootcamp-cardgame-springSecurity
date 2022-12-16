package org.example.cardgame.domain.events;

import org.example.cardgame.domain.values.Alias;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.JugadorId;

public class JuegoFinalizado extends DomainEvent {
    private final JugadorId jugadorId;
    private final Alias alias;

    public JuegoFinalizado(JugadorId jugadorId, Alias alias) {
        super("cardgame.juegofinalizado");
        this.jugadorId = jugadorId;
        this.alias = alias;
    }

    public JugadorId getJugadorId() {
        return jugadorId;
    }

    public Alias getAlias() {
        return alias;
    }
}
