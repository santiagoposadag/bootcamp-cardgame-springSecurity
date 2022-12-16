package org.example.cardgame.domain.command;

import org.example.cardgame.generic.Command;

import java.util.Set;

public class CrearRondaCommand extends Command {

    public CrearRondaCommand(){

    }
    public CrearRondaCommand(String juegoId, Integer tiempo, Set<String> jugadores) {
        this.juegoId = juegoId;
        this.tiempo = tiempo;
        this.jugadores = jugadores;
    }

    private String juegoId;
    private Integer tiempo;
    private Set<String> jugadores;


    public Set<String> getJugadores() {
        return jugadores;
    }

    public void setJugadores(Set<String> jugadores) {
        this.jugadores = jugadores;
    }

    public String getJuegoId() {
        return juegoId;
    }

    public void setJuegoId(String juegoId) {
        this.juegoId = juegoId;
    }

    public Integer getTiempo() {
        return tiempo;
    }

    public void setTiempo(Integer tiempo) {
        this.tiempo = tiempo;
    }
}
