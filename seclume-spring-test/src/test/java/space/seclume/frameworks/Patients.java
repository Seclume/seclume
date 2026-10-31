package space.seclume.frameworks;

import java.util.List;
import java.util.Optional;

import jakarta.data.repository.Delete;
import jakarta.data.repository.Find;
import jakarta.data.repository.Insert;
import jakarta.data.repository.Query;
import jakarta.data.repository.Repository;
import jakarta.data.repository.Update;

/**
 * A Jakarta Data repository of {@link IndexedPatient}s, implemented by
 * Hibernate's annotation processor as {@code Patients_}: nothing in it knows
 * about encryption - the converters encrypt, the blind indexes are plain
 * numeric columns, the deterministic SSN is found by equality.
 */
@Repository
public interface Patients {

    @Insert
    void add(IndexedPatient patient);

    @Insert
    void addAll(List<IndexedPatient> patients);

    @Update
    void update(IndexedPatient patient);

    @Delete
    void remove(IndexedPatient patient);

    @Find
    Optional<IndexedPatient> byId(Long id);

    /** A deterministic attribute: the parameter is encrypted as the attribute is. */
    @Find
    Optional<IndexedPatient> bySsn(String ssn);

    /** {@code in} on a deterministic attribute: each parameter is encrypted. */
    @Query("where ssn in :ssns order by id")
    List<IndexedPatient> bySsns(List<String> ssns);

    /** The candidates under a name's search terms; {@link space.seclume.jpa.StringBlindIndex#find} keeps the matches. */
    @Query("where nameIndex in :terms order by id")
    List<IndexedPatient> byNameIndex(List<Long> terms);

    @Query("where emailIndex in :terms order by id")
    List<IndexedPatient> byEmailIndex(List<Long> terms);

    @Query("where name is null order by id")
    List<IndexedPatient> withoutName();

    @Query("from IndexedPatient order by id")
    List<IndexedPatient> all();
}
