package org.example.cardgame.application.queries.handle.materialize.mazo;

import org.example.cardgame.application.queries.adapter.repo.MazoViewModelRepository;
import org.example.cardgame.application.queries.handle.materialize.MaterializeService;
import org.example.cardgame.application.queries.adapter.repo.model.MazoViewModel;
import org.example.cardgame.domain.events.CartaQuitadaDelMazo;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


@Component
public class HandleCartaQuitadaDelMazo  implements MaterializeService {
    private final MazoViewModelRepository repository;

    public HandleCartaQuitadaDelMazo(MazoViewModelRepository repository) {
        this.repository = repository;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent input) {
        var event = (CartaQuitadaDelMazo) input;

        return repository.findByUid(event.getJugadorId().value()).flatMap(mazo -> {
            var carta = event.getCarta().value();
            //TODO:
            mazo.getCartas().removeIf(c -> carta.cartaId().value().equals(c.getCartaId()));
            return repository.save(mazo);
        }).then();

    }

}
