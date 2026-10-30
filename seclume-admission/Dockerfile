# The webhook and the sidecar it injects, in one image: both jars, Java 25.
#   deploy/build-image.sh <tag>   builds it from the jars the Maven build made.
# Pinned by digest (Dependabot moves it); the tag says which line it follows.
FROM eclipse-temurin:25-jre@sha256:ecdc0adb37bde1a281c4d245a3cd535004b1fc8322d560f5b09463b248c81df0
COPY seclume-admission.jar seclume-heapcheck.jar /opt/seclume/
USER 65532:65532
ENTRYPOINT ["java", "-XX:-UsePerfData", "--enable-native-access=ALL-UNNAMED", \
            "-jar", "/opt/seclume/seclume-admission.jar"]
