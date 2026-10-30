package space.seclume.admission;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * The patch a pod gets, applied as the API server applies it, and what comes
 * out: the folder, the JVM options, the sidecar, the socket - and nothing of
 * the pod's own replaced or repeated.
 */
class InjectionTest {

    private static final Injection.Settings SETTINGS =
            Injection.Settings.of("registry.example/seclume-heapcheck:1");

    private static Map<String, Object> pod(String json) {
        return Json.asObject(Json.parse(json));
    }

    private static Map<String, Object> applied(Map<String, Object> pod,
            Injection.Result result) {
        return Json.asObject(Patches.apply(pod, result.patch()));
    }

    private static Map<String, Object> container(Map<String, Object> pod, String name) {
        for (String list : List.of("containers", "initContainers")) {
            for (Object c : Json.asArray(Json.asObject(pod.get("spec")).get(list))) {
                if (name.equals(Json.asObject(c).get("name"))) {
                    return Json.asObject(c);
                }
            }
        }
        return null;
    }

    private static String env(Map<String, Object> container, String name) {
        for (Object e : Json.asArray(container.get("env"))) {
            if (name.equals(Json.asObject(e).get("name"))) {
                return Json.asString(Json.asObject(e).get("value"));
            }
        }
        return null;
    }

    private static List<Object> volumes(Map<String, Object> pod) {
        return Json.asArray(Json.asObject(pod.get("spec")).get("volumes"));
    }

    private static String annotation(Map<String, Object> pod, String name) {
        return Json.asString(Json.asObject(Json.asObject(pod.get("metadata"))
                .get("annotations")).get(name));
    }

    @Test
    void aPodThatAsksForNothingGetsNothing() {
        Map<String, Object> pod = pod("""
                {"metadata":{"name":"p","annotations":{"seclume.space/redact-dumps":"no"}},
                 "spec":{"containers":[{"name":"app","image":"app"}]}}""");
        Injection.Result result = Injection.mutate(pod, SETTINGS);
        assertEquals(List.of(), result.patch());
        assertEquals(List.of(), Injection.mutate(pod("{\"spec\":{}}"), SETTINGS).patch());
    }

    @Test
    void dumpsGoToAFolderTheSidecarRedacts() {
        Map<String, Object> pod = pod("""
                {"metadata":{"name":"p","annotations":{"seclume.space/redact-dumps":"true",
                  "seclume.space/secret-volumes":"db, nowhere"}},
                 "spec":{"containers":[{"name":"app","image":"app",
                   "securityContext":{"runAsUser":1000,"runAsGroup":1000}}],
                   "volumes":[{"name":"db","secret":{"secretName":"db"}}]}}""");
        Injection.Result result = Injection.mutate(pod, SETTINGS);
        Map<String, Object> after = applied(pod, result);

        assertEquals(List.of("redact-dumps"), result.injected());
        Map<String, Object> app = container(after, "app");
        assertEquals(Injection.JVM_OPTIONS, env(app, "JAVA_TOOL_OPTIONS"));
        assertTrue(Json.write(app.get("volumeMounts")).contains("\"mountPath\":\"/seclume/dumps\""));
        assertEquals(2, volumes(after).size());
        assertTrue(Json.write(volumes(after)).contains("{\"name\":\"seclume-dumps\",\"emptyDir\":{}}"));

        Map<String, Object> sidecar = container(after, Injection.SIDECAR);
        assertEquals("registry.example/seclume-heapcheck:1", sidecar.get("image"));
        List<Object> command = Json.asArray(sidecar.get("command"));
        assertEquals(List.of("--watch", "/seclume/dumps", "--interval", "10s", "--discover",
                "--secret-dir", "/seclume/secrets/db"),
                command.subList(command.indexOf("--watch"), command.size()));
        String mounts = Json.write(sidecar.get("volumeMounts"));
        assertTrue(mounts.contains("{\"name\":\"db\",\"mountPath\":\"/seclume/secrets/db\","
                + "\"readOnly\":true}"), mounts);
        Map<String, Object> context = Json.asObject(sidecar.get("securityContext"));
        assertEquals(new Json.Number("1000"), context.get("runAsUser"),
                "the sidecar is not the application's user, and cannot read its dumps");
        assertEquals(Boolean.TRUE, context.get("readOnlyRootFilesystem"));
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("nowhere")),
                result.warnings().toString());
        assertEquals("redact-dumps", annotation(after, Injection.INJECTED));
    }

    @Test
    void theJvmOptionsOfThePodAreNeitherReplacedNorRepeated() {
        Map<String, Object> pod = pod("""
                {"metadata":{"annotations":{"seclume.space/redact-dumps":"true"}},
                 "spec":{"containers":[
                   {"name":"a","env":[{"name":"JAVA_TOOL_OPTIONS","value":"-Ddb.password=hunter2-in-env"}]},
                   {"name":"b","env":[{"name":"JAVA_TOOL_OPTIONS","value":"-Dx=1"},
                                      {"name":"JDK_JAVA_OPTIONS","value":"-Dy=2"}]}]}}""");
        Injection.Result result = Injection.mutate(pod, SETTINGS);
        Map<String, Object> after = applied(pod, result);

        assertFalse(Json.write(result.patch()).contains("hunter2-in-env"),
                "the patch repeats a value of the pod's");
        Map<String, Object> a = container(after, "a");
        assertEquals("-Ddb.password=hunter2-in-env", env(a, "JAVA_TOOL_OPTIONS"));
        assertEquals(Injection.JVM_OPTIONS, env(a, "JDK_JAVA_OPTIONS"));
        Map<String, Object> b = container(after, "b");
        assertEquals("-Dx=1", env(b, "JAVA_TOOL_OPTIONS"));
        assertEquals("-Dy=2", env(b, "JDK_JAVA_OPTIONS"));
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("container b")),
                result.warnings().toString());
    }

    @Test
    void onlyTheContainersNamedAreChanged() {
        Map<String, Object> pod = pod("""
                {"metadata":{"annotations":{"seclume.space/redact-dumps":"TRUE",
                  "seclume.space/containers":"app, ghost"}},
                 "spec":{"containers":[{"name":"proxy"},{"name":"app"}]}}""");
        Injection.Result result = Injection.mutate(pod, SETTINGS);
        Map<String, Object> after = applied(pod, result);
        assertNull(container(after, "proxy").get("env"));
        assertEquals(Injection.JVM_OPTIONS, env(container(after, "app"), "JAVA_TOOL_OPTIONS"));
        assertTrue(result.warnings().stream().anyMatch(w -> w.contains("ghost")));
    }

    @Test
    void aSecondPassChangesNothing() {
        Map<String, Object> pod = pod("""
                {"metadata":{"annotations":{"seclume.space/redact-dumps":"true",
                  "seclume.space/spiffe":"true"}},
                 "spec":{"containers":[{"name":"app"}]}}""");
        Injection.Result first = Injection.mutate(pod, SETTINGS);
        Map<String, Object> after = applied(pod, first);
        assertEquals(List.of("redact-dumps", "spiffe"), first.injected());
        assertEquals("redact-dumps,spiffe", annotation(after, Injection.INJECTED));
        Injection.Result second = Injection.mutate(after, SETTINGS);
        assertEquals(List.of(), second.patch(), "the pod was changed twice");
    }

    @Test
    void aNativeSidecarIsAnInitContainerThatKeepsRunning() {
        Injection.Settings settings = new Injection.Settings("img", "/x.jar",
                Duration.ofSeconds(2), true, "128Mi", "1Gi", "csi.spiffe.io", null,
                "/spiffe-workload-api", "spire-agent.sock");
        Map<String, Object> pod = pod("""
                {"metadata":{"annotations":{"seclume.space/redact-dumps":"true"}},
                 "spec":{"initContainers":[{"name":"migrate"}],"containers":[{"name":"app"}]}}""");
        Map<String, Object> after = applied(pod, Injection.mutate(pod, settings));
        List<Object> init = Json.asArray(Json.asObject(after.get("spec")).get("initContainers"));
        assertEquals(2, init.size());
        Map<String, Object> sidecar = container(after, Injection.SIDECAR);
        assertEquals("Always", sidecar.get("restartPolicy"));
        assertTrue(Json.asArray(sidecar.get("command")).containsAll(List.of("/x.jar", "2s")));
        assertTrue(Json.write(volumes(after)).contains("\"sizeLimit\":\"1Gi\""));
        assertEquals(1, Json.asArray(Json.asObject(after.get("spec")).get("containers")).size());
    }

    @Test
    void theWorkloadApiSocketIsMountedAndNamed() {
        Map<String, Object> pod = pod("""
                {"metadata":{"annotations":{"seclume.space/spiffe":"true",
                  "seclume.space/injected":"other"}},
                 "spec":{"containers":[{"name":"a"},
                   {"name":"b","env":[{"name":"SPIFFE_ENDPOINT_SOCKET","value":"unix:///own.sock"}]}]}}""");
        Injection.Result result = Injection.mutate(pod, SETTINGS);
        Map<String, Object> after = applied(pod, result);
        assertTrue(Json.write(volumes(after)).contains(
                "{\"name\":\"seclume-spiffe\",\"csi\":"), Json.write(volumes(after)));
        assertEquals("unix:///spiffe-workload-api/spire-agent.sock",
                env(container(after, "a"), "SPIFFE_ENDPOINT_SOCKET"));
        assertEquals("unix:///own.sock", env(container(after, "b"), "SPIFFE_ENDPOINT_SOCKET"));
        assertTrue(Json.write(container(after, "b").get("volumeMounts")).contains(
                "\"readOnly\":true"));
        assertEquals("other,spiffe", annotation(after, Injection.INJECTED));

        Injection.Settings host = new Injection.Settings("img", "/x.jar", Duration.ofSeconds(10),
                false, "256Mi", null, "csi.spiffe.io", "/run/spire/sockets", "/spire",
                "agent.sock");
        Map<String, Object> hostPath = applied(pod, Injection.mutate(pod, host));
        assertTrue(Json.write(volumes(hostPath)).contains("/run/spire/sockets"));
        assertEquals("unix:///spire/agent.sock",
                env(container(hostPath, "a"), "SPIFFE_ENDPOINT_SOCKET"));
    }

    @Test
    void settingsThatCannotWorkAreRefused() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> Injection.Settings.of(" "));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> new Injection.Settings("img", "/x.jar", Duration.ZERO, false, "1Mi",
                        null, "d", null, "/m", "s"));
    }
}
