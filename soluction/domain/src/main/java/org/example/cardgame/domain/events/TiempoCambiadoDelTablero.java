package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.TableroId;
import org.example.cardgame.domain.values.TiempoLimite;

public class TiempoCambiadoDelTablero extends DomainEvent {
    private final TableroId tableroId;
    private final TiempoLimite tiempoLimite;

    public TiempoCambiadoDelTablero(TableroId tableroId, TiempoLimite tiempoLimite) {
        super("cardgame.tiempocambiadodeltablero");
        this.tableroId = tableroId;
        this.tiempoLimite = tiempoLimite;
    }

    public TiempoLimite getTiempoLimite() {
        return tiempoLimite;
    }

    public TableroId getTableroId() {
        return tableroId;
    }
}
