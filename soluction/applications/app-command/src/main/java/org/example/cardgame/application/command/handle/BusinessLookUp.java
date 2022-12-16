package org.example.cardgame.application.command.handle;

import org.example.cardgame.application.command.handle.event.CuentaRegresivaEventHandle;
import org.example.cardgame.application.command.handle.event.DeterminarGanadorEventHandle;
import org.example.cardgame.application.command.handle.event.FinalizarRondaEventHandle;
import org.example.cardgame.application.command.handle.event.RepartirCartaEventHandle;
import org.example.cardgame.generic.BusinessService;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

@Component
public class BusinessLookUp {
    private final Map<String, Flux<BusinessService>> business = new HashMap<>();
    public BusinessLookUp(ApplicationContext context){
        business.put("cardgame.rondaterminada", Flux.just(
                context.getBean(DeterminarGanadorEventHandle.class))
        );
        business.put("cardgame.rondainiciada", Flux.just(
                context.getBean(CuentaRegresivaEventHandle.class)
        ));
        business.put("cardgame.tablerocreado", Flux.just(
                context.getBean(RepartirCartaEventHandle.class)
        ));
        business.put("cardgame.cuentaregresivafinalizada", Flux.just(
                context.getBean(FinalizarRondaEventHandle.class)
        ));
    }

    public Flux<BusinessService> get(String eventType) {
        return business.getOrDefault(eventType, Flux.empty());
    }
}
