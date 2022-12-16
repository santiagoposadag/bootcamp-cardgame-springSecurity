package org.example.cardgame.generic;


import org.example.cardgame.generic.serialize.EventSerializer;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.function.Function;

public class IntegrationHandle implements Function<Flux<DomainEvent>, Mono<Void>> {
    private final String aggregate;
    private final EventStoreRepository repository;
    private final EventPublisher eventPublisher;
    private final EventSerializer eventSerializer;

    public IntegrationHandle(String aggregate, EventStoreRepository repository, EventPublisher eventPublisher, EventSerializer eventSerializer) {
        this.aggregate = aggregate;
        this.repository = repository;
        this.eventPublisher = eventPublisher;
        this.eventSerializer = eventSerializer;
    }

    @Override
    public Mono<Void> apply(Flux<DomainEvent> events) {
        return events.onBackpressureDrop()
                .delayElements(Duration.ofMillis(50))
                .flatMap(domainEvent -> {
                    var stored = StoredEvent.wrapEvent(domainEvent, eventSerializer);
                    return repository.saveEvent(aggregate, domainEvent.aggregateRootId(), stored)
                            .thenReturn(domainEvent);
                }, 1)
                .doOnNext(eventPublisher::publish)
                .onErrorResume(errorEvent -> Mono.create(callback -> {
                    if (errorEvent instanceof BusinessException) {
                        eventPublisher.publishError(errorEvent);
                        callback.success();
                    } else {
                        errorEvent.printStackTrace();
                        callback.error(errorEvent);
                    }
                })).then();
    }


}