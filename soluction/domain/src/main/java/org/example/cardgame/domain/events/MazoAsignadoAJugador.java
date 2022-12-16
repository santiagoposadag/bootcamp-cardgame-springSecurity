package org.example.cardgame.domain.events;

import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.Mazo;
import org.example.cardgame.generic.DomainEvent;

public class MazoAsignadoAJugador extends DomainEvent {
    private final JugadorId jugadorId;
    private final Mazo mazo;

    public MazoAsignadoAJugador(JugadorId jugadorId, Mazo mazo) {
        super("cardgame.mazoasignadoajugador");
        this.jugadorId = jugadorId;
        this.mazo = mazo;
    }

    public Mazo getMazo() {
        return mazo;
    }

    public JugadorId getJugadorId() {
        return jugadorId;
    }
}
