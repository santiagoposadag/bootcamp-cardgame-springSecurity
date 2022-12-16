package org.example.cardgame.domain.values;

import org.example.cardgame.generic.ValueObject;

import java.util.Objects;

public class TiempoLimite implements ValueObject<Integer> {
    private final Integer value;

    public TiempoLimite(Integer value) {
        this.value = Objects.requireNonNull(value);
        if(value <= 0){
            throw new IllegalArgumentException("El valor de ser un tiempo positivo");
        }
    }

    @Override
    public Integer value() {
        return value;
    }
}
