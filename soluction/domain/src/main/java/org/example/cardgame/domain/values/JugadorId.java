package org.example.cardgame.domain.values;

import org.example.cardgame.generic.Identity;

public class JugadorId extends Identity {

    public JugadorId(String value) {
        super(value);
    }

    public JugadorId() {

    }

    public static JugadorId of(String value) {
        return new JugadorId(value);
    }
}
