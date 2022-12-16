package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.events.CuentaRegresivaFinalizada;
import org.example.cardgame.domain.values.Carta;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForEvent;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;

public class FinalizarRondaUseCase extends UseCaseForEvent<CuentaRegresivaFinalizada> {

    private final JuegoDomainEventRepository repository;

    public FinalizarRondaUseCase(JuegoDomainEventRepository repository){
        this.repository = repository;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<CuentaRegresivaFinalizada> cuentaRegresivaFinalizada) {
        return cuentaRegresivaFinalizada.flatMapMany(event -> repository
                .obtenerEventosPor(event.aggregateRootId())
                .collectList()
                .flatMapIterable(events -> {
                    var juego = Juego.from(JuegoId.of(event.aggregateRootId()), events);

                    var partidaOrdenada = obtenerMejorPartidaDel(juego);
                    var competidores = obtenerIdsDeLa(partidaOrdenada);
                    var partida =  partidaOrdenada.firstEntry();
                    if (hayGanadorDe(partida)) {
                        var ganadorId = partida.getValue();
                        var puntos = partida.getKey();
                        juego.devolverCartasAlGanador(
                                ganadorId, puntos, aplanarLasCartasDelTablero(juego, ganadorId)
                        );
                    }
                    juego.terminarRonda(juego.tablero().identity(), competidores);

                    return juego.getUncommittedChanges();
                }));
    }

    private boolean hayGanadorDe(Map.Entry<Integer, JugadorId> partida) {
        return !Objects.isNull(partida);
    }

    private Set<JugadorId> obtenerIdsDeLa(TreeMap<Integer, JugadorId> partidaOrdenada) {
        return new HashSet<>(partidaOrdenada.values());
    }

    private Set<Carta> aplanarLasCartasDelTablero(Juego juego, JugadorId jugadorId) {
        return new HashSet<>(juego.tablero()
                .partida().get(jugadorId));
    }

    private TreeMap<Integer, JugadorId> obtenerMejorPartidaDel(Juego juego) {
        TreeMap<Integer, JugadorId> partidaOrdenada = new TreeMap<>((t1, t2) -> t2 - t1);
        juego.tablero().partida().forEach((jugadorId, cartas) -> {
            cartas.stream()
                    .map(c -> c.value().poder())
                    .reduce(Integer::sum)
                    .ifPresent(puntos -> {
                        partidaOrdenada.put(puntos, jugadorId);
                    });

        });
        return partidaOrdenada;
    }
}
