package org.example.cardgame.application.queries.handle.materialize.tablero;

import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.MazoViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.TiempoCambiadoDelTablero;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;



@Component
public class HandleTiempoCambiadoDelTablero implements MaterializeService {
    private final TableroViewModelRepository repository;

    public HandleTiempoCambiadoDelTablero(TableroViewModelRepository repository) {
        this.repository = repository;
    }


    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (TiempoCambiadoDelTablero)input;

        return repository.findById(event.aggregateRootId()).flatMap(tablero -> {
            tablero.setTiempo(event.getTiempoLimite().value());
            return repository.save(tablero);
        }).then();
    }
}
