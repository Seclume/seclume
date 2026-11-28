package space.seclume.r2dbc;

import java.util.Map;

import reactor.core.publisher.Mono;

/**
 * The session context of a reactive application's connections - its tenant,
 * say - read from where a reactive application keeps it: the Reactor context.
 *
 * <pre>
 * ConnectionFactory factory = SeclumeConnectionFactory.over(pool)
 *         .withSessionContext(() -&gt; Mono.deferContextual(view -&gt;
 *                 Mono.just(Map.of("app.tenant_id", view.get(Tenant.class).id()))));
 * </pre>
 *
 * <p>A pool's blocking supplier is asked on the borrowing thread. Under
 * R2DBC that is an event loop when a connection is free and a thread of the
 * pool's when it has to wait: a {@code ThreadLocal} there is someone else's
 * or nobody's, and the same request ran with its tenant at low load and
 * without it under load. This is resolved on the subscriber, with its
 * context, and handed to the pool by name.
 *
 * <p>An empty Mono or an empty map means no context. An error fails the
 * borrow; no connection has been taken then.
 */
@FunctionalInterface
public interface ReactiveSessionContext {

    /** The context of the connection about to be borrowed, as the subscriber sees it. */
    Mono<Map<String, String>> current();
}
