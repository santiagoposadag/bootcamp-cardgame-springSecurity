package org.example.cardgame.application.queries.handle.materialize.juegolist;

import org.example.cardgame.application.queries.adapter.repo.JuegoListViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.JuegoListViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.JugadorAgregado;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;



@Component
public class HandleJugadorAgregado  implements MaterializeService {
    private final JuegoListViewModelRepository repository;

    public HandleJugadorAgregado(JuegoListViewModelRepository repository) {
        this.repository = repository;
    }


    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (JugadorAgregado)input;
        var juegoListViewModel = repository.findById(event.aggregateRootId());

        return juegoListViewModel.flatMap(juegoList -> {
            var jugador = new JuegoListViewModel.Jugador();
            jugador.setAlias(event.getAlias().value());
            jugador.setJugadorId(event.getJugadorId().value());
            juegoList.getJugadores().put(event.getJugadorId().value(), jugador);
            return repository.save(juegoList);
        }).then();
    }

}
