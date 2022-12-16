package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.Alias;
import org.example.cardgame.domain.values.JugadorId;

public class JugadorAgregado extends DomainEvent {
    private final JugadorId identity;
    private final Alias alias;

    public JugadorAgregado(JugadorId identity, Alias alias) {
        super("cardgame.jugadoragregado");
        this.identity = identity;
        this.alias = alias;
    }

    public JugadorId getJugadorId() {
        return identity;
    }

    public Alias getAlias() {
        return alias;
    }

}
