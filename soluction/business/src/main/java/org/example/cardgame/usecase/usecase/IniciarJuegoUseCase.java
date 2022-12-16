package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.CrearRondaCommand;
import org.example.cardgame.domain.command.IniciarJuegoCommand;
import org.example.cardgame.domain.values.*;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.Identity;
import org.example.cardgame.generic.UseCaseForCommand;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


import java.util.stream.Collectors;

public class IniciarJuegoUseCase extends UseCaseForCommand<IniciarJuegoCommand> {

    private final JuegoDomainEventRepository repository;
    private final CrearRondaUseCase crearRondaUseCase;

    public IniciarJuegoUseCase(JuegoDomainEventRepository repository,  CrearRondaUseCase crearRondaUseCase) {
        this.repository = repository;
        this.crearRondaUseCase = crearRondaUseCase;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<IniciarJuegoCommand> iniciarJuegoCommand) {
        return iniciarJuegoCommand.flatMapMany(command -> repository
                .obtenerEventosPor(command.getJuegoId())
                .collectList()
                .flatMapIterable(events -> {
                    //TODO: validar que sea minimo dos jugadores
                    var juego = Juego.from(JuegoId.of(command.getJuegoId()), events);

                    var jugadoreIds = juego.jugadores().keySet();
                    juego.crearTablero();
                    juego.crearRonda(new Ronda(1,jugadoreIds), new TiempoLimite(20));
                    return juego.getUncommittedChanges();
                }));
    }



}
