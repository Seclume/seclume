package space.seclume.springtest;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

/** The entity with a JSON column, LOBs and a formula. */
public interface NoteRepository extends JpaRepository<Note, Long> {

    /** A filter on the formula - the expression has to land in the where clause. */
    @Query("select n from Note n where n.doubled > :least order by n.id")
    List<Note> findByDoubledAbove(@Param("least") int least);

    /** Bulk HQL: no entity is loaded, and the count is the server's. */
    @Modifying
    @Query("update Note n set n.words = n.words + :by where n.title like :prefix")
    int addWords(@Param("by") int by, @Param("prefix") String prefix);

    @Modifying
    @Query("delete from Note n where n.words < :below")
    int deleteShorterThan(@Param("below") int below);
}
