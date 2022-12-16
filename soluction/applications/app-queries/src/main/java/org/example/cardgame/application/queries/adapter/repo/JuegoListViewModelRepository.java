package org.example.cardgame.application.queries.adapter.repo;



import org.example.cardgame.application.queries.adapter.repo.model.JuegoListViewModel;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;


@Repository
public interface JuegoListViewModelRepository extends ReactiveCrudRepository<JuegoListViewModel, String> {
    Flux<JuegoListViewModel> findAllByUid(String uid);
}
