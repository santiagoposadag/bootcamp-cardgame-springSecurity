package org.example.cardgame.application.master;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;


import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Configuration
public class QueryHandle {

    @Bean
    public RouterFunction<ServerResponse> getList(CartaMaestraService service) {
        return route(
                GET("/list"),
                request -> service.obtenerCartasPepsico()
                        .collectList()
                        .flatMap(list -> ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .bodyValue(list)
        ));
    }


}
