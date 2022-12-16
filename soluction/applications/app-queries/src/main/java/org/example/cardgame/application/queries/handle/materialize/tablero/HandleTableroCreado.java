package org.example.cardgame.application.queries.handle.materialize.tablero;

import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.TableroViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.TableroCreado;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.Identity;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.stream.Collectors;

@Component
public class HandleTableroCreado  implements MaterializeService {
    private final TableroViewModelRepository repository;

    public HandleTableroCreado(TableroViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (TableroCreado)input;
        var tableroViewModel = new TableroViewModel();
        var tablero = new TableroViewModel.Tablero();
        var jugadores = event.getJugadorIds().stream()
                .map(Identity::value)
                .collect(Collectors.toSet());

        tablero.setId(event.getTableroId().value());
        tablero.setCartas(new HashMap<>());
        tablero.setJugadores(jugadores);
        tablero.setHabilitado(false);

        tableroViewModel.setId(event.aggregateRootId());
        tableroViewModel.setTiempo(0);
        tableroViewModel.setTablero(tablero);
        return repository.save(tableroViewModel).then();
    }
}
