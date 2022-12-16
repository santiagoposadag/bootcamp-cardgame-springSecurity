package org.example.cardgame.domain.command;

import org.example.cardgame.generic.Command;


public class CrearJuegoCommand extends Command {
    private String juegoId;
    private String jugadorPrincipalId;
    private String alias;
    private Integer montoRequerido;

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public void setMontoRequerido(Integer montoRequerido) {
        this.montoRequerido = montoRequerido;
    }

    public Integer getMontoRequerido() {
        return montoRequerido;
    }

    public String getJugadorPrincipalId() {
        return jugadorPrincipalId;
    }

    public void setJugadorPrincipalId(String jugadorPrincipalId) {
        this.jugadorPrincipalId = jugadorPrincipalId;
    }

    public String getJuegoId() {
        return juegoId;
    }

    public void setJuegoId(String juegoId) {
        this.juegoId = juegoId;
    }
}
