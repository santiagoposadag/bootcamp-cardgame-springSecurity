package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;

public class CuentaRegresivaFinalizada extends DomainEvent {
    public CuentaRegresivaFinalizada() {
        super("cardgame.cuentaregresivafinalizada");
    }
}
