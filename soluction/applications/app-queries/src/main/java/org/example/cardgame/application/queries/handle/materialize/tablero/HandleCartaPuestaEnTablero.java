package org.example.cardgame.application.queries.handle.materialize.tablero;

import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.MazoViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.CartaPuestaEnTablero;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.HashMap;


@Component
public class HandleCartaPuestaEnTablero implements MaterializeService {
    private final TableroViewModelRepository repository;

    public HandleCartaPuestaEnTablero(TableroViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (CartaPuestaEnTablero)input;
        return repository.findById(event.aggregateRootId()).flatMap(tablero -> {
            var cartaViewModel = new MazoViewModel.Carta();
            var carta = event.getCarta().value();
            cartaViewModel.setCartaId(carta.cartaId().value());
            cartaViewModel.setEstaOculta(carta.estaOculta());
            cartaViewModel.setPoder(carta.poder());
            cartaViewModel.setEstaHabilitada(carta.estaHabilitada());
            cartaViewModel.setJugadorId(event.getJugadorId().value());

            var cartas = tablero.getTablero()
                    .getCartas()
                    .getOrDefault(event.getJugadorId().value(), new HashMap<>());

            cartas.put(carta.cartaId().value(), cartaViewModel);
            tablero.getTablero().getCartas().put(event.getJugadorId().value(), cartas);

            return repository.save(tablero);
        }).then();
    }
}
