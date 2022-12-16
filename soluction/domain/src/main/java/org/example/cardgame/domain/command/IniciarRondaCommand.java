package org.example.cardgame.domain.command;

import org.example.cardgame.generic.Command;

public class IniciarRondaCommand extends Command {
    private String juegoId;

    public String getJuegoId() {
        return juegoId;
    }

    public void setJuegoId(String juegoId) {
        this.juegoId = juegoId;
    }
}
