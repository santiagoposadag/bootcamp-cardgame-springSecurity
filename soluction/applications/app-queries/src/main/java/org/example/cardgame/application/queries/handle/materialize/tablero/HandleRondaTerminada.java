package org.example.cardgame.application.queries.handle.materialize.tablero;

import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.RondaTerminada;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.Identity;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


import java.util.HashMap;
import java.util.stream.Collectors;

@Component
public class HandleRondaTerminada  implements MaterializeService {
    private final TableroViewModelRepository repository;

    public HandleRondaTerminada(TableroViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (RondaTerminada)input;
        return repository.findById(event.aggregateRootId()).flatMap(tablero -> {
            var jugadores = event.getJugadorIds().stream()
                    .map(Identity::value)
                    .collect(Collectors.toSet());
            tablero.setTiempo(0);
            tablero.getRonda().setJugadores(jugadores);
            tablero.getRonda().setEstaIniciada(false);
            tablero.getTablero().setCartas(new HashMap<>());
            tablero.getTablero().setHabilitado(false);
            return repository.save(tablero);
        }).then();
    }
}
