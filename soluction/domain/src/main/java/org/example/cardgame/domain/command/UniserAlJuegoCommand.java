package org.example.cardgame.domain.command;

import org.example.cardgame.domain.Jugador;
import org.example.cardgame.domain.values.Alias;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.generic.Command;


public class UniserAlJuegoCommand extends Command {
    private final JuegoId juegoId;
    private final JugadorId jugadorId;
    private final Alias alias;

    public UniserAlJuegoCommand(JuegoId juegoId, JugadorId jugadorId, Alias alias) {
        this.juegoId = juegoId;
        this.jugadorId = jugadorId;
        this.alias = alias;
    }

    public JuegoId getJuegoId() {
        return juegoId;
    }


    public JugadorId getJugadorId() {
        return jugadorId;
    }


    public Alias getAlias() {
        return alias;
    }

}
