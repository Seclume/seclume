package space.seclume.spring;

import java.util.Map;

/**
 * The session context every borrowed connection carries - declare one as a
 * bean and every seclume data source picks it up.
 *
 * <pre>
 * &#64;Bean
 * SeclumeSessionContext tenant() {
 *     return () -&gt; TenantHolder.current() == null ? Map.of()
 *             : Map.of("app.tenant_id", TenantHolder.current());
 * }
 * </pre>
 *
 * <p>Asked on every borrow, on the borrowing thread - so whatever holds the
 * request's tenant (a {@code ThreadLocal}, a scoped value, Spring Security's
 * context) is what it reads. The pool resets the context when the connection
 * comes back. See {@link space.seclume.SessionContext} for where each
 * database keeps it and how a row-level security policy reads it.
 */
@FunctionalInterface
public interface SeclumeSessionContext {

    /** The context for the connection being borrowed now; empty for none. */
    Map<String, String> current();
}
