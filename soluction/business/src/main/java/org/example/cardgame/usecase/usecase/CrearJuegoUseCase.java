package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.CrearJuegoCommand;
import org.example.cardgame.domain.values.*;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForCommand;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


public class CrearJuegoUseCase extends UseCaseForCommand<CrearJuegoCommand> {

    @Override
    public Flux<DomainEvent> apply(Mono<CrearJuegoCommand> input) {
        return  input.flatMapIterable(command -> {
                        var juego = new Juego(
                                JuegoId.of(command.getJuegoId()),
                                JugadorId.of(command.getJugadorPrincipalId()),
                                new MontoRequerido(command.getMontoRequerido())
                        );

                        juego.asignarJugador(JugadorId.of(command.getJugadorPrincipalId()),new Alias(command.getAlias()));
                        return juego.getUncommittedChanges();
                });
    }


}
