package org.example.cardgame.domain.values;


import org.example.cardgame.generic.ValueObject;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class Mazo implements ValueObject<Mazo.Props> {

    private final Set<Carta> catas;
    private final Integer cantidad;

    public Mazo(Set<Carta> catas) {
        this.catas = Objects.requireNonNull(catas);
        this.cantidad = catas.size();
        if(this.cantidad <= 0){
            throw new IllegalArgumentException("El mazo debe tener cartas, al menos una.");
        }
    }

    @Override
    public Props value() {
        return new Props() {
            @Override
            public Set<Carta> cartas() {
                return catas;
            }

            @Override
            public Integer cantidad() {
                return cantidad;
            }
        };
    }

    public Mazo nuevaCarta(Carta carta) {
        var catas = new HashSet<>(this.catas);
        catas.add(carta);
        return new Mazo(catas);
    }

    public Mazo retirarCarta(Carta cartaRetirada) {
        var cartaId = cartaRetirada.value().cartaId().value();
        Set<Carta> setNuevo = this.catas.stream().filter(
                        carta -> !carta.value().cartaId().value().equals(cartaId))
                .collect(Collectors.toUnmodifiableSet());
        return new Mazo(setNuevo);
    }

    public interface Props {
        Set<Carta> cartas();

        Integer cantidad();
    }
}
