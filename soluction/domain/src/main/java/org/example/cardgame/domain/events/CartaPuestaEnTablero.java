package org.example.cardgame.domain.events;

import org.example.cardgame.domain.values.Carta;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.TableroId;
import org.example.cardgame.generic.DomainEvent;

public class CartaPuestaEnTablero extends DomainEvent {
    private final TableroId tableroId;
    private final JugadorId jugadorId;
    private final Carta carta;

    public CartaPuestaEnTablero(TableroId tableroId, JugadorId jugadorId, Carta carta) {
        super("cardgame.cartapuestaentablero");
        this.tableroId = tableroId;
        this.jugadorId = jugadorId;
        this.carta = carta;
    }

    public TableroId getTableroId() {
        return tableroId;
    }

    public JugadorId getJugadorId() {
        return jugadorId;
    }

    public Carta getCarta() {
        return carta;
    }
}
