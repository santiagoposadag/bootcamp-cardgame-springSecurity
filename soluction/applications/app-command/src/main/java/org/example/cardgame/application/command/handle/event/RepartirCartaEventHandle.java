package org.example.cardgame.application.command.handle.event;


import org.example.cardgame.domain.events.TableroCreado;
import org.example.cardgame.generic.BusinessService;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.IntegrationHandle;
import org.example.cardgame.usecase.usecase.RepartirCartasUseCase;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RepartirCartaEventHandle implements BusinessService {
    private final RepartirCartasUseCase usecase;
    private final IntegrationHandle handle;


    public RepartirCartaEventHandle(RepartirCartasUseCase usecase, IntegrationHandle handle) {
        this.usecase = usecase;
        this.handle = handle;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent event) {
        return handle.apply(usecase.apply(Mono.just((TableroCreado) event)));
    }
}