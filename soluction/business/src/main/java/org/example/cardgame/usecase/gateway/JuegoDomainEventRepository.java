package org.example.cardgame.usecase.gateway;

import org.example.cardgame.generic.DomainEvent;
import reactor.core.publisher.Flux;

public interface JuegoDomainEventRepository {
    Flux<DomainEvent> obtenerEventosPor(String id);
}
