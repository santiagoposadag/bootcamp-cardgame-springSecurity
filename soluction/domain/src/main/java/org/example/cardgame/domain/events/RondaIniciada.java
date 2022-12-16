package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;

public class RondaIniciada extends DomainEvent {
    public RondaIniciada() {
        super("cardgame.rondainiciada");
    }
}
