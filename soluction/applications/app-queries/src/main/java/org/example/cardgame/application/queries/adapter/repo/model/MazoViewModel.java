package org.example.cardgame.application.queries.adapter.repo.model;

import java.util.Objects;
import java.util.Set;

public class MazoViewModel {
    private String id;
    private String uid;
    private String juegoId;
    private Integer cantidad;
    private Set<Carta> cartas;

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setJuegoId(String juegoId) {
        this.juegoId = juegoId;
    }

    public String getJuegoId() {
        return juegoId;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getUid() {
        return uid;
    }

    public Integer getCantidad() {
        return cantidad;
    }

    public void setCantidad(Integer cantidad) {
        this.cantidad = cantidad;
    }

    public Set<Carta> getCartas() {
        return cartas;
    }

    public void setCartas(Set<Carta> cartas) {
        this.cartas = cartas;
    }

    public static class Carta{
        private  String cartaId;
        private  String jugadorId;
        private  Boolean estaOculta;
        private  Boolean estaHabilitada;
        private  Integer poder;

        public String getCartaId() {
            return cartaId;
        }

        public void setCartaId(String cartaId) {
            this.cartaId = cartaId;
        }

        public String getJugadorId() {
            return jugadorId;
        }

        public void setJugadorId(String jugadorId) {
            this.jugadorId = jugadorId;
        }

        public Boolean getEstaOculta() {
            return estaOculta;
        }

        public void setEstaOculta(Boolean estaOculta) {
            this.estaOculta = estaOculta;
        }

        public Boolean getEstaHabilitada() {
            return estaHabilitada;
        }

        public void setEstaHabilitada(Boolean estaHabilitada) {
            this.estaHabilitada = estaHabilitada;
        }

        public Integer getPoder() {
            return poder;
        }

        public void setPoder(Integer poder) {
            this.poder = poder;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Carta carta = (Carta) o;
            return cartaId.equals(carta.cartaId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(cartaId);
        }
    }
}
