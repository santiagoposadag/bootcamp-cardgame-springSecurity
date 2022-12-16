package org.example.cardgame.usecase.usecase;

import org.example.cardgame.domain.Juego;
import org.example.cardgame.domain.command.PonerCartaEnTablero;
import org.example.cardgame.domain.values.CartaMaestraId;
import org.example.cardgame.domain.values.JuegoId;
import org.example.cardgame.domain.values.JugadorId;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.UseCaseForCommand;
import org.example.cardgame.usecase.gateway.JuegoDomainEventRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


public class PonerCartaEnTableroUseCase extends UseCaseForCommand<PonerCartaEnTablero> {
    private final JuegoDomainEventRepository repository;

    public PonerCartaEnTableroUseCase(JuegoDomainEventRepository repository) {
        this.repository = repository;
    }

    @Override
    public Flux<DomainEvent> apply(Mono<PonerCartaEnTablero> ponerCartaEnTablero) {
        return ponerCartaEnTablero.flatMapMany(command -> repository
                .obtenerEventosPor(command.getJuegoId())
                .collectList()
                .flatMapIterable(events -> {
                    //TODO: servicio de dominio para obtener monedas de la billetera
                    var juego = Juego.from(JuegoId.of(command.getJuegoId()), events);

                    var tableroId = juego.tablero().identity();
                    var jugadorId = JugadorId.of(command.getJugadorId());
                    var cartaId = CartaMaestraId.of(command.getCartaId());
                    var cartaSeleccionado = juego.obtenerCartaDelMazoDelJugador(jugadorId, cartaId);

                    juego.ponerCartaEnTablero(tableroId, jugadorId, cartaSeleccionado);
                    return juego.getUncommittedChanges();
                }));
    }
}
