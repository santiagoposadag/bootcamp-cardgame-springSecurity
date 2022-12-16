package org.example.cardgame.domain.values;


import org.example.cardgame.generic.ValueObject;

import java.util.Objects;

public class Alias implements ValueObject<String> {
    private final String value;

    public Alias(String value) {
        this.value = Objects.requireNonNull(value);
        if(this.value.isEmpty()){
            throw new IllegalArgumentException("El alias no es valido");
        }
    }

    @Override
    public String value() {
        return value;
    }
}
