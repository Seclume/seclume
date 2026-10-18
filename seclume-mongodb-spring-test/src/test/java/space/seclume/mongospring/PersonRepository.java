package space.seclume.mongospring;

import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

public interface PersonRepository extends MongoRepository<Person, String> {

    Optional<Person> findByEmail(String email);

    List<Person> findByAgeGreaterThanOrderByAgeAsc(int age);

    Page<Person> findByAddressCity(String city, Pageable page);

    List<Person> findByTagsContaining(String tag);

    long countByAgeBetween(int from, int to);

    @Query("{ 'name': { $regex: ?0 } }")
    List<Person> namesMatching(String pattern);

    @Aggregation("{ $group: { _id: '$address.city', n: { $sum: 1 } } }")
    List<CityCount> perCity();

    long deleteByAgeLessThan(int age);

    record CityCount(String id, int n) {
    }
}
