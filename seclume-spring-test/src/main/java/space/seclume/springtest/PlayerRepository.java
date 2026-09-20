package space.seclume.springtest;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

/** The many side, and the owner of the many-to-many and the shared key. */
public interface PlayerRepository extends JpaRepository<Player, Long> {

    Optional<Player> findByLabel(String label);
}
