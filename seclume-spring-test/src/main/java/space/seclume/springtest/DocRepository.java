package space.seclume.springtest;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

/** Reads the union over the per-class tables. */
public interface DocRepository extends JpaRepository<Doc, Long> {

    Optional<Doc> findByDocNo(String docNo);
}
