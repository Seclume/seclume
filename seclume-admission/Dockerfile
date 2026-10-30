# The webhook and the sidecar it injects, in one image: both jars, Java 25.
#   deploy/build-image.sh <tag>   builds it from the jars the Maven build made.
FROM eclipse-temurin:25-jre
COPY seclume-admission.jar seclume-heapcheck.jar /opt/seclume/
USER 65532:65532
ENTRYPOINT ["java", "-XX:-UsePerfData", "--enable-native-access=ALL-UNNAMED", \
            "-jar", "/opt/seclume/seclume-admission.jar"]
