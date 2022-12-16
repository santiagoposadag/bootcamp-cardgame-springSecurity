package org.example.cardgame.application.command.handle.event;


import org.example.cardgame.domain.events.CuentaRegresivaFinalizada;
import org.example.cardgame.generic.BusinessService;
import org.example.cardgame.generic.DomainEvent;
import org.example.cardgame.generic.IntegrationHandle;
import org.example.cardgame.usecase.usecase.FinalizarRondaUseCase;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class FinalizarRondaEventHandle implements BusinessService {
    private final FinalizarRondaUseCase usecase;
    private final IntegrationHandle handle;


    public FinalizarRondaEventHandle(FinalizarRondaUseCase usecase, IntegrationHandle handle) {
        this.usecase = usecase;
        this.handle = handle;
    }

    @Override
    public Mono<Void> doProcessing(DomainEvent event) {
        return handle.apply(usecase.apply(Mono.just((CuentaRegresivaFinalizada) event)));
    }
}