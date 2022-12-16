package org.example.cardgame.application.queries.adapter.repo.model;

import java.time.Instant;
import java.util.Map;

public class JuegoListViewModel {
    private String id;
    private Boolean iniciado;
    private Boolean finalizado;
    private String uid;
    private Instant fecha;
    private Map<String, Jugador> jugadores;
    private Jugador ganador;


    public Instant getFecha() {
        return fecha;
    }

    public void setFecha(Instant fecha) {
        this.fecha = fecha;
    }

    public void setGanador(Jugador ganador) {
        this.ganador = ganador;
    }

    public Jugador getGanador() {
        return ganador;
    }

    public void setFinalizado(Boolean finalizado) {
        this.finalizado = finalizado;
    }

    public Boolean getFinalizado() {
        return finalizado;
    }


    public Map<String, Jugador> getJugadores() {
        return jugadores;
    }

    public void setJugadores(Map<String, Jugador> jugadores) {
        this.jugadores = jugadores;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Boolean getIniciado() {
        return iniciado;
    }

    public void setIniciado(Boolean iniciado) {
        this.iniciado = iniciado;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getUid() {
        return uid;
    }

    public static class Jugador {
        private String alias;
        private String jugadorId;

        public void setAlias(String alias) {
            this.alias = alias;
        }

        public String getAlias() {
            return alias;
        }

        public void setJugadorId(String jugadorId) {
            this.jugadorId = jugadorId;
        }

        public String getJugadorId() {
            return jugadorId;
        }
    }
}
