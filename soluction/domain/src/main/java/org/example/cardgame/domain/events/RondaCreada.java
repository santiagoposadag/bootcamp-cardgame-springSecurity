package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.Ronda;
import org.example.cardgame.domain.values.TiempoLimite;

public class RondaCreada extends DomainEvent {
    private final Ronda ronda;
    private final TiempoLimite tiempoLimite;

    public RondaCreada(Ronda ronda, TiempoLimite tiempoLimite) {
        super("cardgame.rondacreada");
        this.ronda = ronda;
        this.tiempoLimite = tiempoLimite;
    }

    public Ronda getRonda() {
        return ronda;
    }

    public TiempoLimite getTiempoLimite() {
        return tiempoLimite;
    }
}
