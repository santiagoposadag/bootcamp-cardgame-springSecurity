package org.example.cardgame.application.master;

import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

@Service
public class CartaMaestraService {
    private final ReactiveMongoTemplate template;

    public CartaMaestraService(ReactiveMongoTemplate template) {
        this.template = template;
    }


    public Flux<CartaMaestra> obtenerCartasPepsico() {
        return template.findAll(CartaMaestra.class, "cards");
    }
}
