package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.UniserAlJuegoCommand;
import org.example.cardgame.domain.values.Alias;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForCommand;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


public class UnirseAlJuegoUseCase extends UseCaseForCommand<UniserAlJuegoCommand> {
    private final JuegoDomainEventRepository repository;

    public UnirseAlJuegoUseCase(JuegoDomainEventRepository repository) {
        this.repository = repository;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<UniserAlJuegoCommand> uniserAlJuegoCommand) {
        return   uniserAlJuegoCommand.flatMapMany((command) -> repository
                .obtenerEventosPor(command.getJuegoId().value())
                .collectList()
                .flatMapIterable(events -> {
                    //TODO: la regla para el monto minimo
                    var juego = Juego.from(command.getJuegoId(), events);
                    var jugadorId = command.getJugadorId();
                    juego.asignarJugador(jugadorId, command.getAlias());
                    return juego.getUncommittedChanges();
                }));
    }



}
