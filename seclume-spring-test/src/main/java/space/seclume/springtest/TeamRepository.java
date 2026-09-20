package space.seclume.springtest;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * The ordered collection, fetched in the same query as its owner.
 *
 * <p>Only one collection is in the graph on purpose. Fetching two of them at
 * once is a join of both against the owner, so every row of one appears once
 * per row of the other - a cartesian product that JPA allows and that has
 * nothing to do with the driver. The tags are read on their own, which is
 * what an application should do too.
 */
public interface TeamRepository extends JpaRepository<Team, Long> {

    @EntityGraph(attributePaths = "players")
    Optional<Team> findByLabel(String label);
}
