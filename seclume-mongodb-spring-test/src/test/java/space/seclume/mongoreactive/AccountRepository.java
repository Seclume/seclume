package space.seclume.mongoreactive;

import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface AccountRepository extends ReactiveMongoRepository<Account, String> {

    Flux<Account> findByBalanceGreaterThan(long balance, Sort sort);

    Mono<Account> findByOwner(String owner);

    Mono<Long> countByBalanceLessThan(long balance);
}
