package org.example.cardgame.domain.values;

import org.example.cardgame.generic.ValueObject;

import java.util.Objects;

public class MontoRequerido implements ValueObject<Integer> {
    private final Integer value;

    public MontoRequerido(Integer value) {
        this.value = Objects.requireNonNull(value);
        if(value <= 0){
            throw new IllegalArgumentException("El valor debe un monto positivo");
        }
    }

    @Override
    public Integer value() {
        return value;
    }
}
