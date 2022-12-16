package org.example.cardgame.application.queries.handle.materialize.mazo;

import org.example.cardgame.application.queries.adapter.repo.MazoViewModelRepository;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.application.queries.adapter.repo.model.MazoViewModel;
import org.example.cardgame.domain.events.CartasAsignadasAJugador;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;



@Component
public class HandleCartasAsignadasAJugador  implements MaterializeService {
    private final MazoViewModelRepository repository;

    public HandleCartasAsignadasAJugador(MazoViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (CartasAsignadasAJugador)input;
        return repository.findByJuegoIdAndUid(event.aggregateRootId(), event.getGanadorId().value()).flatMap(mazo -> {
            event.getCartasApuesta().forEach(carta -> {
                var cartaModelView = new MazoViewModel.Carta();
                cartaModelView.setEstaHabilitada(carta.value().estaHabilitada());
                cartaModelView.setEstaOculta(carta.value().estaOculta());
                cartaModelView.setPoder(carta.value().poder());
                cartaModelView.setCartaId(carta.value().cartaId().value());
                cartaModelView.setJugadorId(event.getGanadorId().value());
                mazo.getCartas().add(cartaModelView);
            });
            return repository.save(mazo);
        }).then();


    }
}
