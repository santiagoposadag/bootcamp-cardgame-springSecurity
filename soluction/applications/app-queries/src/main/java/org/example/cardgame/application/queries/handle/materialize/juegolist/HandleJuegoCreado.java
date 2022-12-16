package org.example.cardgame.application.queries.handle.materialize.juegolist;

import org.example.cardgame.application.queries.adapter.repo.JuegoListViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.JuegoListViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.JuegoCreado;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;

@Component
public class HandleJuegoCreado  implements MaterializeService {

    private final JuegoListViewModelRepository repository;

    public HandleJuegoCreado(JuegoListViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (JuegoCreado)input;
        var juegoListViewModel = new JuegoListViewModel();

        juegoListViewModel.setFecha(Instant.now());
        juegoListViewModel.setId(event.aggregateRootId());
        juegoListViewModel.setIniciado(false);
        juegoListViewModel.setUid(event.getJugadorPrincipal().value());
        juegoListViewModel.setFinalizado(false);
        juegoListViewModel.setJugadores(new HashMap<>());

        return repository.save(juegoListViewModel).then();
    }
}
