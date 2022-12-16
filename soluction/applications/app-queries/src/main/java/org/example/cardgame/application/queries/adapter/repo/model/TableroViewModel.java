package org.example.cardgame.application.queries.adapter.repo.model;

import java.util.Map;
import java.util.Set;

public class TableroViewModel {
    private String id;
    private Tablero tablero;
    private Integer tiempo;
    private Ronda ronda;


    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Tablero getTablero() {
        return tablero;
    }

    public void setTablero(Tablero tablero) {
        this.tablero = tablero;
    }

    public Integer getTiempo() {
        return tiempo;
    }

    public void setTiempo(Integer tiempo) {
        this.tiempo = tiempo;
    }

    public Ronda getRonda() {
        return ronda;
    }

    public void setRonda(Ronda ronda) {
        this.ronda = ronda;
    }

    public static class Tablero{
        private String id;
        private Set<String> jugadores;
        private Boolean habilitado;
        private Map<String, Map<String, MazoViewModel.Carta>> cartas;


        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public Set<String> getJugadores() {
            return jugadores;
        }

        public void setJugadores(Set<String> jugadores) {
            this.jugadores = jugadores;
        }

        public Boolean getHabilitado() {
            return habilitado;
        }

        public void setHabilitado(Boolean habilitado) {
            this.habilitado = habilitado;
        }

        public void setCartas(Map<String, Map<String, MazoViewModel.Carta>> cartas) {
            this.cartas = cartas;
        }

        public Map<String, Map<String, MazoViewModel.Carta>> getCartas() {
            return cartas;
        }
    }

    public static class Ronda{
        private Set<String> jugadores;
        private Integer numero;
        private Boolean estaIniciada;

        public Set<String> getJugadores() {
            return jugadores;
        }

        public void setJugadores(Set<String> jugadores) {
            this.jugadores = jugadores;
        }

        public Integer getNumero() {
            return numero;
        }

        public void setNumero(Integer numero) {
            this.numero = numero;
        }

        public Boolean getEstaIniciada() {
            return estaIniciada;
        }

        public void setEstaIniciada(Boolean estaIniciada) {
            this.estaIniciada = estaIniciada;
        }
    }
}
