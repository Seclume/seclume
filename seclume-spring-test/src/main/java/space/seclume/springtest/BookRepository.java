package space.seclume.springtest;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

/** The entity spread over two tables. */
public interface BookRepository extends JpaRepository<Book, Long> {

    Optional<Book> findByIsbn(String isbn);
}
