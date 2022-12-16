package org.example.cardgame.application.queries.handle.materialize.tablero;

import org.bson.Document;
import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.TableroViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.RondaCreada;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.Identity;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class HandleRondaCreada  implements MaterializeService {

    private final TableroViewModelRepository repository;

    public HandleRondaCreada(TableroViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (RondaCreada)input;
        return repository.findById(event.aggregateRootId()).flatMap(tablero -> {
            var rondaModelView = new TableroViewModel.Ronda();
            var ronda = event.getRonda().value();
            var jugadores = ronda.jugadores().stream()
                    .map(Identity::value)
                    .collect(Collectors.toSet());

            rondaModelView.setJugadores(jugadores);
            rondaModelView.setEstaIniciada(false);
            rondaModelView.setNumero(ronda.numero());
            tablero.setTiempo(event.getTiempoLimite().value());
            tablero.setRonda(rondaModelView);
            tablero.getTablero().setHabilitado(false);
            return repository.save(tablero);
        }).then();

    }
}
