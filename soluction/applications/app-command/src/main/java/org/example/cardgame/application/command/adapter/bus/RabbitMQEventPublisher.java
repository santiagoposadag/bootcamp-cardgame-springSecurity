package org.example.cardgame.application.command.adapter.bus;

import brave.Span;
import brave.Tracer;
import org.example.cardgame.application.command.ConfigProperties;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.ErrorEvent;
import org.example.cardgame.generic.EventPublisher;
import org.example.cardgame.generic.serialize.EventSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.rabbitmq.OutboundMessage;
import reactor.rabbitmq.Sender;

@Service
public class RabbitMQEventPublisher implements EventPublisher {
    private static final Logger LOGGER = LoggerFactory.getLogger(RabbitMQEventPublisher.class);
    private final Tracer tracer;

    private final Sender sender;
    private final EventSerializer eventSerializer;
    private final ConfigProperties configProperties;

    public RabbitMQEventPublisher(Tracer tracer, Sender sender, EventSerializer eventSerializer, ConfigProperties configProperties) {
        this.tracer = tracer;
        this.sender = sender;
        this.eventSerializer = eventSerializer;
        this.configProperties = configProperties;
    }

    @Override
    public void publish(DomainEvent event) {
        var eventBody = eventSerializer.serialize(event);

        Span span = createSpan(event, eventBody).start();
        var notification = new Notification(
                event.getClass().getTypeName(),
                eventBody,
                span.context().traceId(),
                span.context().parentId(),
                span.context().spanId(),
                span.context().extra()
        );
        sender.sendWithPublishConfirms(buildOutboundMessage(event.type, notification))
                .doOnError(e -> LOGGER.error("Send failed", e))
                .subscribe(m -> {
                    if(m.isAck()) {
                        LOGGER.info(String.format("Message sent %s", event.type));
                        span.finish();
                    }
                });

    }

    private Span createSpan(DomainEvent event, String eventBody) {
        return tracer.nextSpan()
                .name("publisher")
                .tag("eventType", event.type)
                .tag("aggregateRootId", event.aggregateRootId())
                .tag("aggregate", event.getAggregateName())
                .tag("uuid", event.uuid.toString())
                .annotate(eventBody)
                .remoteServiceName("rabbitmq")
                .kind(Span.Kind.CLIENT);
    }

    @Override
    public void publishError(Throwable errorEvent) {
        var event = new ErrorEvent(errorEvent.getClass().getTypeName(), errorEvent.getMessage());
        var notification = new Notification(
                event.getClass().getTypeName(),
                eventSerializer.serialize(event),
                null, null, null, null);
        sender.sendWithPublishConfirms(buildOutboundMessage(event.type, notification))
                .doOnError(e -> LOGGER.error("Send failed", e))
                .subscribe(m -> {
                    if(m.isAck()) {
                        LOGGER.info(String.format("Message sent %s", event.type));
                    }
                });
    }

    private Mono<OutboundMessage> buildOutboundMessage(String eventType, Notification notification) {
        return  Mono.just(new OutboundMessage(
                configProperties.getExchange(), eventType, notification.serialize().getBytes()
        ));
    }




}