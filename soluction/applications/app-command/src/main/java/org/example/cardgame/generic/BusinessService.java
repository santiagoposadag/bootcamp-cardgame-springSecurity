package org.example.cardgame.generic;

import reactor.core.publisher.Mono;

public interface BusinessService{
   Mono<Void> doProcessing(DomainEvent event);
}