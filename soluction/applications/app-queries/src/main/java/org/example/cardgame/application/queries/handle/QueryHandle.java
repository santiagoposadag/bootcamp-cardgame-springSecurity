package org.example.cardgame.application.queries.handle;



import org.example.cardgame.application.queries.adapter.repo.JuegoListViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.MazoViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.TableroViewModelRepository;
import org.example.cardgame.application.queries.adapter.repo.model.JuegoListViewModel;
import org.example.cardgame.application.queries.adapter.repo.model.MazoViewModel;
import org.example.cardgame.application.queries.adapter.repo.model.TableroViewModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;


import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Configuration
public class QueryHandle {


    private final JuegoListViewModelRepository juegoListViewModelRepository;
    private final MazoViewModelRepository mazoViewModelRepository;
    private final TableroViewModelRepository tableroViewModelRepository;

    public QueryHandle(JuegoListViewModelRepository juegoListViewModelRepository, MazoViewModelRepository mazoViewModelRepository, TableroViewModelRepository tableroViewModelRepository) {

        this.juegoListViewModelRepository = juegoListViewModelRepository;
        this.mazoViewModelRepository = mazoViewModelRepository;
        this.tableroViewModelRepository = tableroViewModelRepository;
    }

    @Bean
    public RouterFunction<ServerResponse> listarJuego() {
        return route(
                GET("/juego/listar/{uid}"),
                request -> juegoListViewModelRepository.findAllByUid(request.pathVariable("uid"))
                        .collectList()
                        .flatMap(list -> ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(BodyInserters.fromPublisher(Flux.fromIterable(list), JuegoListViewModel.class)))
        );
    }


    @Bean
    public RouterFunction<ServerResponse> obtenerTablero() {
        return route(
                GET("/juego/tablero/{id}"),
                request -> tableroViewModelRepository.findById(request.pathVariable("id"))
                        .flatMap(element -> ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(BodyInserters.fromPublisher(Mono.just(element), TableroViewModel.class)))
        );
    }

    @Bean
    public RouterFunction<ServerResponse> obtenerMazo() {
        return route(
                GET("/juego/mazo/{juegoId}/{uid}"),
                request -> mazoViewModelRepository.findByJuegoIdAndUid( request.pathVariable("juegoId"),  request.pathVariable("uid"))
                        .flatMap(element -> ServerResponse.ok()
                                .contentType(MediaType.APPLICATION_JSON)
                                .body(BodyInserters.fromPublisher(Mono.just(element), MazoViewModel.class)))
        );
    }

}
