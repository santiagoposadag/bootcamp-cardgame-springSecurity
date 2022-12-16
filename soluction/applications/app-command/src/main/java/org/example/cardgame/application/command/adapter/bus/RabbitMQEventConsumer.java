package org.example.cardgame.application.command.adapter.bus;


import brave.Span;
import brave.Tracer;
import brave.propagation.TraceContext;
import org.example.cardgame.application.command.ConfigProperties;
import org.example.cardgame.application.command.GsonEventSerializer;
import org.example.cardgame.application.command.handle.BusinessLookUp;
import org.example.cardgame.generic.DomainEvent;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.rabbitmq.AcknowledgableDelivery;
import reactor.rabbitmq.ConsumeOptions;
import reactor.rabbitmq.ExceptionHandlers;
import reactor.rabbitmq.Receiver;

import java.time.Duration;



@Component
public class RabbitMQEventConsumer implements CommandLineRunner {
    private final Tracer tracer;
    private final GsonEventSerializer serializer;
    private final ConfigProperties configProperties;
    private final Receiver receiver;
    private final BusinessLookUp businessLookUp;

    public RabbitMQEventConsumer(Tracer tracer,  GsonEventSerializer serializer, ConfigProperties configProperties, Receiver receiver, BusinessLookUp businessLookUp) {
        this.tracer = tracer;
        this.serializer = serializer;
        this.configProperties = configProperties;
        this.receiver = receiver;
        this.businessLookUp = businessLookUp;
    }


    @Override
    public void run(String... args) {
        receiver.consumeManualAck(configProperties.getQueue(), new ConsumeOptions()
                .exceptionHandler(new ExceptionHandlers.RetryAcknowledgmentExceptionHandler(
                        Duration.ofSeconds(20), Duration.ofMillis(500),
                        ExceptionHandlers.CONNECTION_RECOVERY_PREDICATE
                )))
                .onBackpressureBuffer()
                .flatMapSequential(message -> {
                    var notification = Notification.from(new String(message.getBody()));
                    var context = TraceContext.newBuilder()
                            .parentId(notification.getParentId())
                            .spanId(notification.getSpanId())
                            .traceId(notification.getTraceId())
                            .build();
                    try {
                        var event = serializer.deserialize(
                                notification.getBody(), Class.forName(notification.getType())
                        );
                        Span span = createSpan(notification, context, event);
                        return businessLookUp.get(event.type)
                                .doFirst(span::start)
                                .flatMap(materializeService -> materializeService.doProcessing(event))
                                .then(Mono.defer(() -> {
                                    span.finish();
                                    return Mono.just(message);
                                }));
                    } catch (ClassNotFoundException e) {
                        throw new IllegalArgumentException();
                    }

                }, 1).subscribe(AcknowledgableDelivery::ack);
    }

    private Span createSpan(Notification notification, TraceContext context, DomainEvent event) {
        return tracer.newChild(context)
                .name("consumer")
                .tag("eventType", event.type)
                .tag("aggregateRootId", event.aggregateRootId())
                .tag("aggregate", event.getAggregateName())
                .tag("uuid", event.uuid.toString())
                .annotate(notification.getBody())
                .kind(Span.Kind.SERVER);
    }
}
