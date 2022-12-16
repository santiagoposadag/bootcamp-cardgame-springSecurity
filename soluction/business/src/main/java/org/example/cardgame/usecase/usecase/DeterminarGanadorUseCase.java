package org.example.cardgame.usecase.usecase;


import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.Jugador;
import org.example.cardgame.domain.command.CrearRondaCommand;
import org.example.cardgame.domain.events.RondaTerminada;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForEvent;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class DeterminarGanadorUseCase  extends UseCaseForEvent<RondaTerminada> {
    private final JuegoDomainEventRepository repository;
    private final CrearRondaUseCase crearRondaUseCase;

    public DeterminarGanadorUseCase(JuegoDomainEventRepository repository, CrearRondaUseCase crearRondaUseCase){
        this.repository = repository;
        this.crearRondaUseCase = crearRondaUseCase;
    }


    @Override
    public Flux<DomainEvent> apply(Mono<RondaTerminada> rondaTerminadaMono) {
        return rondaTerminadaMono.flatMapMany((event) -> repository
                .obtenerEventosPor(event.aggregateRootId())
                .collectList()
                .flatMapMany(events -> {
                    var juego = Juego.from(JuegoId.of(event.aggregateRootId()), events);
                    var jugadores = jugadoresConCartas(juego);
                    var competidores = event.getJugadorIds();

                    intentoDeFinalizarPorInexistenciaDeJugadores(juego, jugadores);
                    intentoDeFinalizarPorInexistenciaDeCompetidores(juego, competidores);

                    if(noHayGanadorDel(juego)){
                        return crearNuevaRonda(event, juego, jugadores);
                    }
                    return Flux.fromIterable(juego.getUncommittedChanges());
                }));
    }

    private boolean noHayGanadorDel(Juego juego) {
        return Objects.isNull(juego.ganador());
    }

    private List<Jugador> jugadoresConCartas(Juego juego) {
        return juego.jugadores().values().stream()
                .filter(jugador -> jugador.mazo().value().cantidad() > 0)
                .collect(Collectors.toList());
    }

    private void intentoDeFinalizarPorInexistenciaDeJugadores(Juego juego, List<Jugador> jugadores) {
        if(jugadores.size()  == 1) {
            var jugador = jugadores.get(0);
            juego.finalizarJuego(jugador.identity(), jugador.alias());
        }
    }

    private void intentoDeFinalizarPorInexistenciaDeCompetidores(Juego juego, Set<JugadorId> competidores) {
        if (competidores.size() == 1){
            competidores.stream().findFirst().ifPresent(jugadorId -> {
                var jugador = juego.jugadores().get(jugadorId);
                juego.finalizarJuego(jugador.identity(), jugador.alias());
            });
        }
    }

    private Flux<DomainEvent> crearNuevaRonda(RondaTerminada event, Juego juego, List<Jugador> jugadores) {
        var command = new CrearRondaCommand();
        var jugadoresIds = jugadores.stream()
                .map(a -> a.identity().value())
                .collect(Collectors.toSet());
        command.setJuegoId(event.aggregateRootId());
        command.setTiempo(20);
        command.setJugadores(jugadoresIds);
        return crearRondaUseCase.apply(Mono.just(command))
                .mergeWith(Flux.fromIterable(juego.getUncommittedChanges()));
    }
}