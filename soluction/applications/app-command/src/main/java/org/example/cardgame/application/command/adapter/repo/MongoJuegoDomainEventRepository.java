package org.example.cardgame.application.command.adapter.repo;

import org.example.cardgame.application.command.ConfigProperties;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.EventStoreRepository;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

@Component
public class MongoJuegoDomainEventRepository implements JuegoDomainEventRepository {
    private final EventStoreRepository repository;
    private final ConfigProperties configProperties;

    public MongoJuegoDomainEventRepository(EventStoreRepository repository, ConfigProperties configProperties) {
        this.repository = repository;
        this.configProperties = configProperties;
    }


    @Override
    public Flux<DomainEvent> obtenerEventosPor(String id) {
        return repository.getEventsBy(configProperties.getStoreName(), id);
    }
}
