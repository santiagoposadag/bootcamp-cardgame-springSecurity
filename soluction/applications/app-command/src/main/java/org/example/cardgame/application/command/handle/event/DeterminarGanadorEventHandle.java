package org.example.cardgame.application.command.handle.event;


import org.example.cardgame.domain.events.RondaTerminada;
import org.example.cardgame.generic.BusinessService;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.IntegrationHandle;
import org.example.cardgame.usecase.usecase.DeterminarGanadorUseCase;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class DeterminarGanadorEventHandle implements BusinessService {
    private final DeterminarGanadorUseCase usecase;
    private final IntegrationHandle handle;


    public DeterminarGanadorEventHandle(DeterminarGanadorUseCase usecase, IntegrationHandle handle) {
        this.usecase = usecase;
        this.handle = handle;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent event) {
        return handle.apply(usecase.apply(Mono.just((RondaTerminada)event)));
    }
}