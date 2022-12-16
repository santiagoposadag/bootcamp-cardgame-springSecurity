package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.CrearRondaCommand;
import org.example.cardgame.domain.events.TableroCreado;
import org.example.cardgame.domain.values.Carta;
import org.example.cardgame.domain.values.CartaMaestraId;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.Mazo;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.Identity;
import org.example.cardgame.generic.UseCaseForEvent;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import org.example.cardgame.usecase.gateway.ListaDeCartaService;
import org.example.cardgame.usecase.gateway.model.CartaMaestra;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

public class RepartirCartasUseCase extends UseCaseForEvent<TableroCreado> {
    private final ListaDeCartaService listaDeCartaService;
    private final JuegoDomainEventRepository repository;

    public RepartirCartasUseCase(ListaDeCartaService listaDeCartaService, JuegoDomainEventRepository repository) {
        this.listaDeCartaService = listaDeCartaService;
        this.repository = repository;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<TableroCreado> tableroCreadoMono) {

        return tableroCreadoMono.flatMapMany(event -> repository
                .obtenerEventosPor(event.aggregateRootId())
                .collectList()
                .flatMapMany(events -> {
                    var juego = Juego.from(JuegoId.of(event.aggregateRootId()), events);

                    return listaDeCartaService.obtenerCartasPepsico().collectList().flatMapIterable(cartas -> {
                        var jugadoreIds = juego.jugadores().keySet();

                        jugadoreIds.forEach(jugadorId -> juego.asignarMazoAJugador(jugadorId, generarMazo(cartas)));

                        return juego.getUncommittedChanges();
                    });
                }));
    }


    private Mazo generarMazo(List<CartaMaestra> cartas) {

        Collections.shuffle(cartas);
        var lista = cartas.stream().limit(6)
                .map(carta -> new Carta(CartaMaestraId.of(carta.getId()), carta.getPoder(), false, true))
                .collect(Collectors.toList());
        cartas.removeIf(cartaMaestra -> lista.stream().anyMatch(carta -> {
            var id = carta.value().cartaId().value();
            return cartaMaestra.getId().equals(id);
        }));
        return new Mazo(new HashSet<>(lista));
    }
}
