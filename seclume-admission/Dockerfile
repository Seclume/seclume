# The webhook and the sidecar it injects, in one image: both jars, Java 25.
#   deploy/build-image.sh <tag>   builds it from the jars the Maven build made.
# Pinned by digest (Dependabot moves it); the tag says which line it follows.
FROM eclipse-temurin:25-jre@sha256:4ed132f6832e9804b123e89a849a7b4502756ae64a4ee08ebab939d9d5d0a9fa
COPY seclume-admission.jar seclume-heapcheck.jar /opt/seclume/
USER 65532:65532
ENTRYPOINT ["java", "-XX:-UsePerfData", "--enable-native-access=ALL-UNNAMED", \
            "-jar", "/opt/seclume/seclume-admission.jar"]
