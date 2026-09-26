package space.seclume;

import java.sql.SQLException;

/**
 * A value the database can see for the rest of this session - the tenant a
 * row-level security policy filters by, the user an audit trigger records.
 *
 * <p>Row-level security is usually wired with a statement the application
 * writes itself, {@code SET app.tenant_id = 42}, and that has two failure
 * modes: it is forgotten on one code path, and it outlives the request on a
 * pooled connection. Here the pool sets the context on every borrow (see
 * {@code PoolSettings.setSessionContext}) and resets it on every return, and
 * the value never enters a statement text unquoted.
 *
 * <p>Where each server keeps it, and how a policy reads it:
 *
 * <table>
 *   <caption>setSessionContext("app.tenant_id", "42")</caption>
 *   <tr><td>PostgreSQL</td><td>{@code set_config} - read with {@code current_setting('app.tenant_id')};
 *       the name needs a dot, as every custom setting does</td></tr>
 *   <tr><td>MySQL</td><td>a user variable - read with {@code @app_tenant_id}, the dots made underscores</td></tr>
 *   <tr><td>SQL Server</td><td>{@code sp_set_session_context} - read with
 *       {@code SESSION_CONTEXT(N'app.tenant_id')}</td></tr>
 *   <tr><td>Oracle</td><td>only {@code client_identifier}, read with
 *       {@code SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER')}: any other application
 *       context needs a namespace a DBA creates, with a package of its own</td></tr>
 * </table>
 *
 * <p>PostgreSQL and MySQL send it with the next statement, in the same round
 * trip; SQL Server with the next plain statement, or at once before a prepared
 * one; Oracle at once.
 */
public interface SessionContext {

    /**
     * Sets {@code name} to {@code value} for this session.
     *
     * @param name  letters, digits, underscores and dots, starting with a letter
     * @param value any text; {@code null} is refused - a context that is not
     *              known is left out, not set to nothing
     */
    void setSessionContext(String name, String value) throws SQLException;
}
