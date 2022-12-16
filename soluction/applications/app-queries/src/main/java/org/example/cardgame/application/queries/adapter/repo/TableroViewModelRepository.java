package org.example.cardgame.application.queries.adapter.repo;


import org.example.cardgame.application.queries.adapter.repo.model.TableroViewModel;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TableroViewModelRepository extends ReactiveCrudRepository<TableroViewModel, String> {

}
