package org.example.cardgame.application.queries.handle.materialize.mazo;

import org.example.cardgame.application.queries.adapter.repo.MazoViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.MazoViewModel;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.domain.events.MazoAsignadoAJugador;
import org.example.cardgame.domain.values.Carta;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.stream.Collectors;

@Component
public class HandleMazoAgregado  implements MaterializeService {
    private final MazoViewModelRepository repository;

    public HandleMazoAgregado(MazoViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (MazoAsignadoAJugador)input;
        var mazoViewModel = new MazoViewModel();
        var mazo = event.getMazo().value();

        Set<MazoViewModel.Carta> cartas =  mazo.cartas().stream().map(Carta::value).map(carta -> {
            var cartaModelView = new MazoViewModel.Carta();
            cartaModelView.setCartaId(carta.cartaId().value());
            cartaModelView.setPoder(carta.poder());
            cartaModelView.setEstaOculta(carta.estaOculta());
            cartaModelView.setEstaHabilitada(carta.estaHabilitada());
            cartaModelView.setJugadorId(event.getJugadorId().value());
            return cartaModelView;
        }).collect(Collectors.toSet());

        mazoViewModel.setId(event.uuid.toString());
        mazoViewModel.setUid(event.getJugadorId().value());
        mazoViewModel.setJuegoId(event.aggregateRootId());
        mazoViewModel.setCantidad(event.getMazo().value().cantidad());
        mazoViewModel.setCartas(cartas);

        return repository.save(mazoViewModel).then();
    }
}
