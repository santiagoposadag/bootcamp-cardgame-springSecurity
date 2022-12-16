package org.example.cardgame.generic;


public interface EventPublisher {

    void publish(DomainEvent event);

    void publishError(Throwable errorEvent);
}