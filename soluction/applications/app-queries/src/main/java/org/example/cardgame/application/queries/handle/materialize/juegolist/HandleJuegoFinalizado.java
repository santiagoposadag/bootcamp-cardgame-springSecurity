package org.example.cardgame.application.queries.handle.materialize.juegolist;

import org.example.cardgame.application.queries.adapter.repo.JuegoListViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.JuegoListViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.JuegoFinalizado;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;



@Component
public class HandleJuegoFinalizado  implements MaterializeService {
    private final JuegoListViewModelRepository repository;

    public HandleJuegoFinalizado(JuegoListViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (JuegoFinalizado)input;
        return repository.findById(event.aggregateRootId()).flatMap(juegoList -> {
            var jugador = new JuegoListViewModel.Jugador();
            jugador.setJugadorId(event.getJugadorId().value());
            jugador.setAlias(event.getAlias().value());
            juegoList.setFinalizado(true);
            juegoList.setGanador(jugador);
            return repository.save(juegoList);
        }).then();
    }
}
