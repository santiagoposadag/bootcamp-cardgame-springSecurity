package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.FinalizarRondaCommand;
import org.example.cardgame.domain.events.RondaIniciada;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.TiempoLimite;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForEvent;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

public class IniciarCuentaRegresivaUseCase extends UseCaseForEvent<RondaIniciada> {

    private final JuegoDomainEventRepository repository;

    public IniciarCuentaRegresivaUseCase(JuegoDomainEventRepository repository){
        this.repository = repository;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<RondaIniciada> rondaIniciada) {
        AtomicInteger acumulador = new AtomicInteger(0);
        var finalizarCommand = new FinalizarRondaCommand();
        return rondaIniciada.flatMapMany(event -> repository
                .obtenerEventosPor(event.aggregateRootId())
                .collectList()
                .flatMapMany(events -> {
                    var juego = Juego.from(JuegoId.of(event.aggregateRootId()), events);
                    finalizarCommand.setJuegoId(event.aggregateRootId());
                    var tiempo = juego.tablero().tiempoLimite().value();
                    var tableroId = juego.tablero().identity();
                    return Flux.interval(Duration.ofSeconds(1))
                            .onBackpressureBuffer(1)
                            .take(tiempo)
                            .flatMap(t -> {
                                juego.markChangesAsCommitted();
                                var nuevoTiempo = tiempo - acumulador.getAndIncrement();
                                juego.cambiarTiempoDelTablero(tableroId, new TiempoLimite(nuevoTiempo));
                                return Flux.fromIterable(juego.getUncommittedChanges());
                            });
                }));
    }
}