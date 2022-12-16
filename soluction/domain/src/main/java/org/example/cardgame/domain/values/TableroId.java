package org.example.cardgame.domain.values;

import org.example.cardgame.generic.Identity;

public class TableroId extends Identity {

        public TableroId(String tableroId) {
        super(tableroId);
    }

    public TableroId() {

    }
    public static TableroId of(String tableroId) {
        return new TableroId(tableroId);
    }
}
