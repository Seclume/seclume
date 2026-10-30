package space.seclume.admission;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What the webhook does to a pod: a JSON patch from the pod's annotations.
 *
 * <ul>
 * <li>{@value #REDACT}{@code : "true"} - an {@code emptyDir} at {@value #DUMPS}
 *     in the pod's containers, the JVM told to write its
 *     {@code OutOfMemoryError} dump there, and a sidecar running
 *     {@code seclume-heapcheck --watch} on it: every finished heap dump and
 *     Flight Recorder recording is redacted where it lies and the original
 *     deleted. {@value #SECRET_VOLUMES} names pod volumes - a mounted
 *     Kubernetes secret - whose files the sidecar looks for as well.</li>
 * <li>{@value #SPIFFE}{@code : "true"} - the SPIFFE Workload API socket
 *     (the SPIFFE CSI driver's volume, or a host directory) mounted read-only,
 *     and {@code SPIFFE_ENDPOINT_SOCKET} pointing at it, which seclume-keys'
 *     {@code spiffe=} bundles read.</li>
 * <li>{@value #CONTAINERS} limits both to the containers named; all of the
 *     pod's containers otherwise.</li>
 * </ul>
 *
 * <p>Nothing the pod sets is replaced: a container that already has
 * {@code JAVA_TOOL_OPTIONS} gets the options as {@code JDK_JAVA_OPTIONS},
 * one with both gets a warning instead. The patch never repeats a value of
 * the pod's - an environment variable may hold a password - and applying it
 * twice changes nothing: what is injected is recorded in {@value #INJECTED}
 * and found again by its names.
 */
final class Injection {

    static final String PREFIX = "seclume.space/";
    static final String REDACT = PREFIX + "redact-dumps";
    static final String SECRET_VOLUMES = PREFIX + "secret-volumes";
    static final String SPIFFE = PREFIX + "spiffe";
    static final String CONTAINERS = PREFIX + "containers";
    static final String INJECTED = PREFIX + "injected";

    static final String DUMPS_VOLUME = "seclume-dumps";
    static final String DUMPS = "/seclume/dumps";
    static final String SIDECAR = "seclume-redact-dumps";
    static final String SECRETS = "/seclume/secrets/";
    static final String SPIFFE_VOLUME = "seclume-spiffe";
    static final String JVM_OPTIONS = "-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=" + DUMPS;

    /**
     * How the webhook injects.
     *
     * @param sidecarImage    the image the sidecar runs, with Java 25 and the heapcheck jar
     * @param heapcheckJar    where the jar is in that image
     * @param interval        how often the sidecar looks at the folder
     * @param nativeSidecar   whether the sidecar is a native one - an init container that
     *                        keeps running ({@code restartPolicy: Always}, Kubernetes 1.29+),
     *                        which does not keep a Job's pod from completing
     * @param sidecarMemory   the sidecar's memory request and limit, {@code 256Mi}
     * @param dumpSizeLimit   the folder's {@code sizeLimit}, or {@code null} for none
     * @param spiffeCsiDriver the CSI driver of the Workload API volume, {@code csi.spiffe.io}
     * @param spiffeHostPath  a host directory with the socket instead of the CSI driver, or
     *                        {@code null}
     * @param spiffeMountPath where the socket's directory is mounted
     * @param spiffeSocket    the socket's file name in it
     */
    record Settings(String sidecarImage, String heapcheckJar, Duration interval,
            boolean nativeSidecar, String sidecarMemory, String dumpSizeLimit,
            String spiffeCsiDriver, String spiffeHostPath, String spiffeMountPath,
            String spiffeSocket) {

        Settings {
            if (sidecarImage == null || sidecarImage.isBlank()) {
                throw new IllegalArgumentException("the sidecar needs an image: one with "
                        + "Java 25 and seclume-heapcheck.jar");
            }
            if (interval.isNegative() || interval.toSeconds() < 1) {
                throw new IllegalArgumentException("the sidecar looks at the folder every "
                        + "second at most, not every " + interval);
            }
        }

        /** The defaults, with the sidecar's image. */
        static Settings of(String sidecarImage) {
            return new Settings(sidecarImage, "/opt/seclume/seclume-heapcheck.jar",
                    Duration.ofSeconds(10), false, "256Mi", null, "csi.spiffe.io", null,
                    "/spiffe-workload-api", "spire-agent.sock");
        }
    }

    /**
     * The outcome for one pod.
     *
     * @param patch    JSON patch operations, empty when there is nothing to do
     * @param warnings what was asked for and not done, for the API server to pass on
     * @param injected what was done: {@code redact-dumps}, {@code spiffe}
     */
    record Result(List<Map<String, Object>> patch, List<String> warnings, List<String> injected) {
    }

    private Injection() {
    }

    /** The patch for {@code pod}, a pod as the API server sends it. */
    static Result mutate(Map<String, Object> pod, Settings settings) {
        Map<String, Object> metadata = Json.asObject(pod.get("metadata"));
        Map<String, Object> annotations = Json.asObject(metadata.get("annotations"));
        boolean dumps = yes(annotations.get(REDACT));
        boolean spiffe = yes(annotations.get(SPIFFE));
        Patch patch = new Patch(Json.asObject(pod.get("spec")));
        if (!dumps && !spiffe) {
            return new Result(List.of(), List.of(), List.of());
        }
        List<Integer> targets = patch.targets(Json.asString(annotations.get(CONTAINERS)));
        List<String> injected = new ArrayList<>();
        if (dumps && patch.redactDumps(targets, Json.asString(annotations.get(SECRET_VOLUMES)),
                settings)) {
            injected.add("redact-dumps");
        }
        if (spiffe && patch.spiffe(targets, settings)) {
            injected.add("spiffe");
        }
        if (!injected.isEmpty()) {
            Set<String> all = new LinkedHashSet<>();
            String before = Json.asString(annotations.get(INJECTED));
            if (before != null) {
                for (String part : before.split(",")) {
                    if (!part.isBlank()) {
                        all.add(part.strip());
                    }
                }
            }
            all.addAll(injected);
            patch.add(INJECTED_PATH, String.join(",", all), annotations.containsKey(INJECTED));
        }
        return new Result(List.copyOf(patch.ops), List.copyOf(patch.warnings),
                List.copyOf(injected));
    }

    private static final String INJECTED_PATH = "/metadata/annotations/" + pointer(INJECTED);

    private static boolean yes(Object value) {
        return value instanceof String s && s.strip().equalsIgnoreCase("true");
    }

    /** A JSON pointer's escaping of one name. */
    static String pointer(String name) {
        return name.replace("~", "~0").replace("/", "~1");
    }

    /** The operations, and what the pod has at each point they are added. */
    private static final class Patch {

        final List<Map<String, Object>> ops = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();
        private final Map<String, Object> spec;
        private final List<Object> containers;
        private final Set<String> volumeNames = new LinkedHashSet<>();
        private boolean volumes;
        private boolean initContainers;
        private final Map<Integer, Boolean> env = new LinkedHashMap<>();
        private final Map<Integer, Boolean> mounts = new LinkedHashMap<>();

        Patch(Map<String, Object> spec) {
            this.spec = spec;
            this.containers = Json.asArray(spec.get("containers"));
            this.volumes = spec.get("volumes") instanceof List<?>;
            this.initContainers = spec.get("initContainers") instanceof List<?>;
            for (Object volume : Json.asArray(spec.get("volumes"))) {
                String name = Json.asString(Json.asObject(volume).get("name"));
                if (name != null) {
                    volumeNames.add(name);
                }
            }
        }

        void add(String path, Object value, boolean replace) {
            Map<String, Object> op = new LinkedHashMap<>();
            op.put("op", replace ? "replace" : "add");
            op.put("path", path);
            op.put("value", value);
            ops.add(op);
        }

        private Map<String, Object> container(int index) {
            return Json.asObject(containers.get(index));
        }

        private String name(int index) {
            return String.valueOf(container(index).get("name"));
        }

        /** The containers named in the annotation, or all of them. */
        List<Integer> targets(String named) {
            List<Integer> all = new ArrayList<>();
            for (int i = 0; i < containers.size(); i++) {
                all.add(i);
            }
            if (named == null || named.isBlank()) {
                return all;
            }
            List<Integer> chosen = new ArrayList<>();
            for (String name : named.split(",")) {
                String wanted = name.strip();
                int found = -1;
                for (int i : all) {
                    if (wanted.equals(name(i))) {
                        found = i;
                    }
                }
                if (found < 0) {
                    warnings.add("seclume: " + CONTAINERS + " names " + wanted
                            + ", which is not a container of this pod");
                } else if (!chosen.contains(found)) {
                    chosen.add(found);
                }
            }
            return chosen;
        }

        private boolean hasContainer(String name) {
            for (String list : List.of("containers", "initContainers")) {
                for (Object container : Json.asArray(spec.get(list))) {
                    if (name.equals(Json.asObject(container).get("name"))) {
                        return true;
                    }
                }
            }
            return false;
        }

        private void volume(Map<String, Object> volume) {
            if (volumes) {
                add("/spec/volumes/-", volume, false);
            } else {
                add("/spec/volumes", new ArrayList<>(List.of(volume)), false);
                volumes = true;
            }
            volumeNames.add(String.valueOf(volume.get("name")));
        }

        private boolean mountedAt(int index, String path) {
            for (Object mount : Json.asArray(container(index).get("volumeMounts"))) {
                if (path.equals(Json.asObject(mount).get("mountPath"))) {
                    return true;
                }
            }
            return false;
        }

        private void mount(int index, Map<String, Object> mount) {
            boolean exists = mounts.computeIfAbsent(index,
                    i -> container(i).get("volumeMounts") instanceof List<?>);
            if (exists) {
                add("/spec/containers/" + index + "/volumeMounts/-", mount, false);
            } else {
                add("/spec/containers/" + index + "/volumeMounts",
                        new ArrayList<>(List.of(mount)), false);
                mounts.put(index, true);
            }
        }

        private boolean hasEnv(int index, String name) {
            for (Object variable : Json.asArray(container(index).get("env"))) {
                if (name.equals(Json.asObject(variable).get("name"))) {
                    return true;
                }
            }
            return false;
        }

        private void env(int index, String name, String value) {
            Map<String, Object> variable = new LinkedHashMap<>();
            variable.put("name", name);
            variable.put("value", value);
            boolean exists = env.computeIfAbsent(index,
                    i -> container(i).get("env") instanceof List<?>);
            if (exists) {
                add("/spec/containers/" + index + "/env/-", variable, false);
            } else {
                add("/spec/containers/" + index + "/env", new ArrayList<>(List.of(variable)),
                        false);
                env.put(index, true);
            }
        }

        boolean redactDumps(List<Integer> targets, String secretVolumes, Settings settings) {
            if (volumeNames.contains(DUMPS_VOLUME) || hasContainer(SIDECAR)) {
                return false;                     // there already
            }
            Map<String, Object> emptyDir = new LinkedHashMap<>();
            if (settings.dumpSizeLimit() != null) {
                emptyDir.put("sizeLimit", settings.dumpSizeLimit());
            }
            Map<String, Object> volume = new LinkedHashMap<>();
            volume.put("name", DUMPS_VOLUME);
            volume.put("emptyDir", emptyDir);
            volume(volume);
            Map<String, Object> securityContext = null;
            for (int index : targets) {
                if (mountedAt(index, DUMPS)) {
                    warnings.add("seclume: container " + name(index) + " has something at "
                            + DUMPS + " already, so its dumps are not redacted");
                    continue;
                }
                mount(index, mountOf(DUMPS_VOLUME, DUMPS, false));
                if (!hasEnv(index, "JAVA_TOOL_OPTIONS")) {
                    env(index, "JAVA_TOOL_OPTIONS", JVM_OPTIONS);
                } else if (!hasEnv(index, "JDK_JAVA_OPTIONS")) {
                    env(index, "JDK_JAVA_OPTIONS", JVM_OPTIONS);
                } else {
                    warnings.add("seclume: container " + name(index) + " sets JAVA_TOOL_OPTIONS "
                            + "and JDK_JAVA_OPTIONS - add " + JVM_OPTIONS + " to one of them, "
                            + "or its dumps go elsewhere");
                }
                if (securityContext == null) {
                    securityContext = Json.asObject(container(index).get("securityContext"));
                }
            }

            List<Object> command = new ArrayList<>(List.of("java", "-XX:+UseSerialGC",
                    "-XX:-UsePerfData", "-XX:MaxRAMPercentage=75",
                    "--enable-native-access=ALL-UNNAMED", "-jar", settings.heapcheckJar(),
                    "--watch", DUMPS, "--interval", settings.interval().toSeconds() + "s",
                    "--discover"));
            List<Object> sidecarMounts = new ArrayList<>(List.of(
                    mountOf(DUMPS_VOLUME, DUMPS, false)));
            if (secretVolumes != null) {
                for (String part : secretVolumes.split(",")) {
                    String name = part.strip();
                    if (name.isEmpty()) {
                        continue;
                    }
                    if (!volumeNames.contains(name) || name.startsWith("seclume-")) {
                        warnings.add("seclume: " + SECRET_VOLUMES + " names " + name
                                + ", which is not a volume of this pod");
                        continue;
                    }
                    sidecarMounts.add(mountOf(name, SECRETS + name, true));
                    command.add("--secret-dir");
                    command.add(SECRETS + name);
                }
            }
            Map<String, Object> sidecar = new LinkedHashMap<>();
            sidecar.put("name", SIDECAR);
            sidecar.put("image", settings.sidecarImage());
            sidecar.put("command", command);
            sidecar.put("volumeMounts", sidecarMounts);
            sidecar.put("resources", Map.of(
                    "requests", Map.of("memory", settings.sidecarMemory(), "cpu", "10m"),
                    "limits", Map.of("memory", settings.sidecarMemory())));
            // The dumps are the application's, written readable by their owner
            // only: the sidecar is that user, and can do nothing else.
            Map<String, Object> context = new LinkedHashMap<>();
            for (String id : List.of("runAsUser", "runAsGroup", "runAsNonRoot")) {
                if (securityContext != null && securityContext.containsKey(id)) {
                    context.put(id, securityContext.get(id));
                }
            }
            context.put("allowPrivilegeEscalation", Boolean.FALSE);
            context.put("readOnlyRootFilesystem", Boolean.TRUE);
            context.put("capabilities", Map.of("drop", List.of("ALL")));
            sidecar.put("securityContext", context);
            if (settings.nativeSidecar()) {
                sidecar.put("restartPolicy", "Always");
                if (initContainers) {
                    add("/spec/initContainers/-", sidecar, false);
                } else {
                    add("/spec/initContainers", new ArrayList<>(List.of(sidecar)), false);
                    initContainers = true;
                }
            } else {
                add("/spec/containers/-", sidecar, false);
            }
            return true;
        }

        boolean spiffe(List<Integer> targets, Settings settings) {
            if (volumeNames.contains(SPIFFE_VOLUME)) {
                return false;
            }
            Map<String, Object> volume = new LinkedHashMap<>();
            volume.put("name", SPIFFE_VOLUME);
            if (settings.spiffeHostPath() != null) {
                volume.put("hostPath", Map.of("path", settings.spiffeHostPath(),
                        "type", "Directory"));
            } else {
                volume.put("csi", Map.of("driver", settings.spiffeCsiDriver(),
                        "readOnly", Boolean.TRUE));
            }
            volume(volume);
            String socket = "unix://" + settings.spiffeMountPath() + "/" + settings.spiffeSocket();
            for (int index : targets) {
                if (mountedAt(index, settings.spiffeMountPath())) {
                    warnings.add("seclume: container " + name(index) + " has something at "
                            + settings.spiffeMountPath() + " already, so the Workload API "
                            + "socket is not mounted there");
                    continue;
                }
                mount(index, mountOf(SPIFFE_VOLUME, settings.spiffeMountPath(), true));
                if (!hasEnv(index, "SPIFFE_ENDPOINT_SOCKET")) {
                    env(index, "SPIFFE_ENDPOINT_SOCKET", socket);
                }
            }
            return true;
        }

        private static Map<String, Object> mountOf(String volume, String path,
                boolean readOnly) {
            Map<String, Object> mount = new LinkedHashMap<>();
            mount.put("name", volume);
            mount.put("mountPath", path);
            if (readOnly) {
                mount.put("readOnly", Boolean.TRUE);
            }
            return mount;
        }
    }
}
