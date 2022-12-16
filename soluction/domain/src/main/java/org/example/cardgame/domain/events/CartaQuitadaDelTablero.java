package org.example.cardgame.domain.events;

import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.domain.values.Carta;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.TableroId;

public class CartaQuitadaDelTablero extends DomainEvent {
    private final TableroId tableroId;
    private final JugadorId jugadorId;
    private final Carta carta;

    public CartaQuitadaDelTablero(TableroId tableroId, JugadorId jugadorId, Carta carta) {
        super("cardgame.cartaquitadadeltablero");
        this.tableroId = tableroId;
        this.jugadorId = jugadorId;
        this.carta = carta;
    }

    public Carta getCarta() {
        return carta;
    }

    public JugadorId getJugadorId() {
        return jugadorId;
    }

    public TableroId getTableroId() {
        return tableroId;
    }
}
