package org.example.cardgame.application.queries.handle.materialize;

import org.example.cardgame.generic.DomainEvent;
import reactor.core.publisher.Mono;

public interface MaterializeService{
   Mono<Void> doProcessing(DomainEvent input);
}