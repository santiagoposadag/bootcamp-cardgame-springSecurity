package org.example.cardgame.domain.values;

import org.example.cardgame.generic.Identity;

public class JuegoId extends Identity {
    public JuegoId(String juegoId) {
        super(juegoId);
    }

    public JuegoId() {

    }

    public static JuegoId of(String juegoId) {
        return new JuegoId(juegoId);
    }
}
