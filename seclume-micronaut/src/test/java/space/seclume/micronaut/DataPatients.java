package space.seclume.micronaut;

import java.util.List;

import io.micronaut.data.jdbc.annotation.JdbcRepository;
import io.micronaut.data.model.query.builder.sql.Dialect;
import io.micronaut.data.repository.CrudRepository;

/**
 * A Micronaut Data JDBC repository, implemented at compile time, over
 * whatever {@code DataSource} the context has - here seclume's pool.
 */
@JdbcRepository(dialect = Dialect.POSTGRES)
public interface DataPatients extends CrudRepository<DataPatient, Long> {

    List<DataPatient> findByWardOrderById(String ward);

    long countByWard(String ward);
}
