package org.example.cardgame.domain;

import org.example.cardgame.domain.values.Carta;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.TableroId;
import org.example.cardgame.domain.values.TiempoLimite;
import org.example.cardgame.generic.Entity;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Tablero extends Entity<TableroId> {
    private final Map<JugadorId, Set<Carta>> partida;
    private TiempoLimite tiempoLimite;
    private Boolean estaHabilitado;

    public Tablero(TableroId entityId, Set<JugadorId> jugadorIds) {
        super(entityId);
        this.partida = new HashMap<>();
        this.estaHabilitado = false;
        jugadorIds.forEach(jugadorId -> partida.put(jugadorId, new HashSet<>()));
    }

    public void ajustarTiempo(TiempoLimite tiempoLimite) {
        this.tiempoLimite = tiempoLimite;
    }

    public void adicionarPartida(JugadorId jugadorId, Carta carta) {
        partida.getOrDefault(jugadorId, new HashSet<>()).add(carta);
    }

    public void quitarCarta(JugadorId jugadorId, Carta carta) {
        partida.getOrDefault(jugadorId, new HashSet<>()).remove(carta);
    }

    public void reiniciarPartida() {
        partida.clear();
    }

    public void habilitarApuesta() {
        this.estaHabilitado = true;
    }

    public void inhabilitarApuesta() {
        this.estaHabilitado = false;
    }

    public TiempoLimite tiempoLimite() {
        return tiempoLimite;
    }

    public Boolean estaHabilitado() {
        return estaHabilitado;
    }

    public Map<JugadorId, Set<Carta>> partida() {
        return partida;
    }
}
