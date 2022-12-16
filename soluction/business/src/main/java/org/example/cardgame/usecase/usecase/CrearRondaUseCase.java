package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.CrearRondaCommand;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.domain.values.Ronda;
import org.example.cardgame.domain.values.TiempoLimite;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForCommand;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.stream.Collectors;

public class CrearRondaUseCase extends UseCaseForCommand<CrearRondaCommand> {

    private final JuegoDomainEventRepository repository;

    public CrearRondaUseCase(JuegoDomainEventRepository repository) {
        this.repository = repository;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<CrearRondaCommand> crearRondaCommand) {
        return crearRondaCommand.flatMapMany(command -> repository
                .obtenerEventosPor(command.getJuegoId())
                .collectList()
                .flatMapIterable(events -> {
                    var juego = Juego.from(JuegoId.of(command.getJuegoId()), events);
                    var jugadores = command.getJugadores().stream()
                            .map(JugadorId::of)
                            .collect(Collectors.toSet());

                    var ronda = Optional.ofNullable(juego.ronda())
                            .orElseThrow(() -> new IllegalArgumentException("Es necesaria la primera ronda"));
                    juego.crearRonda(
                            ronda.incrementarRonda(jugadores),
                            new TiempoLimite(command.getTiempo())
                    );
                    return juego.getUncommittedChanges();
                }));
    }
}
