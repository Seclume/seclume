package space.seclume.admission;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A JSON patch applied as the API server applies one: add and replace, for the tests. */
final class Patches {

    private Patches() {
    }

    @SuppressWarnings("unchecked")
    static Object apply(Object document, List<Map<String, Object>> patch) {
        Object root = copy(document);
        for (Map<String, Object> op : patch) {
            String path = (String) op.get("path");
            String[] parts = path.substring(1).split("/", -1);
            Object parent = root;
            for (int i = 0; i < parts.length - 1; i++) {
                parent = child(parent, unescape(parts[i]));
            }
            String last = unescape(parts[parts.length - 1]);
            Object value = copy(op.get("value"));
            switch ((String) op.get("op")) {
                case "add" -> {
                    if (parent instanceof List<?> list) {
                        List<Object> l = (List<Object>) list;
                        if ("-".equals(last)) {
                            l.add(value);
                        } else {
                            l.add(index(last, path), value);
                        }
                    } else {
                        Map<String, Object> m = (Map<String, Object>) parent;
                        if (m == null) {
                            throw new IllegalStateException("no parent for " + path);
                        }
                        m.put(last, value);
                    }
                }
                case "replace" -> {
                    Map<String, Object> m = (Map<String, Object>) parent;
                    if (!m.containsKey(last)) {
                        throw new IllegalStateException("nothing to replace at " + path);
                    }
                    m.put(last, value);
                }
                default -> throw new IllegalStateException("unexpected op " + op);
            }
        }
        return root;
    }

    private static Object child(Object parent, String name) {
        Object child = parent instanceof List<?> list ? list.get(index(name, name))
                : ((Map<?, ?>) parent).get(name);
        if (child == null) {
            throw new IllegalStateException("the path goes through " + name
                    + ", which is not there - the API server would refuse the patch");
        }
        return child;
    }

    /** An array index of a JSON pointer, or a patch the API server would refuse. */
    private static int index(String part, String path) {
        try {
            return Integer.parseInt(part);
        } catch (NumberFormatException notAnIndex) {
            throw new IllegalStateException("not an array index in " + path, notAnIndex);
        }
    }

    private static String unescape(String part) {
        return part.replace("~1", "/").replace("~0", "~");
    }

    private static Object copy(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            map.forEach((k, v) -> copy.put(String.valueOf(k), copy(v)));
            return copy;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>();
            list.forEach(v -> copy.add(copy(v)));
            return copy;
        }
        return value;
    }
}
