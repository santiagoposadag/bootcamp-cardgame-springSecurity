package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.TableroId;

import java.util.Set;

public class RondaTerminada extends DomainEvent {
    private final TableroId tableroId;
    private final Set<JugadorId> jugadorIds;

    public RondaTerminada(TableroId tableroId, Set<JugadorId> jugadorIds) {
        super("cardgame.rondaterminada");
        this.tableroId = tableroId;
        this.jugadorIds = jugadorIds;
    }

    public TableroId getTableroId() {
        return tableroId;
    }

    public Set<JugadorId> getJugadorIds() {
        return jugadorIds;
    }
}
