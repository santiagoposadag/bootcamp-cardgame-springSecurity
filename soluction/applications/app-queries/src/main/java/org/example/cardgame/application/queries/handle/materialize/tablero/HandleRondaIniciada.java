package org.example.cardgame.application.queries.handle.materialize.tablero;

import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.RondaIniciada;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;



@Component
public class HandleRondaIniciada  implements MaterializeService {
    private final TableroViewModelRepository repository;

    public HandleRondaIniciada(TableroViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (RondaIniciada)input;
        return repository.findById(event.aggregateRootId()).flatMap(tablero -> {
            tablero.getTablero().setHabilitado(true);
            tablero.getRonda().setEstaIniciada(true);
            return repository.save(tablero);
        }).then();
    }
}
