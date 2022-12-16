## mvn clean package -DskipTests
## docker build -t xtsofka/cardgame-command .
## docker run --rm -p 8081:8081 xtsofka/cardgame-command
## docker run --rm -p 8081:8081 --network host xtsofka/cardgame-command
## docker push xtsofka/cardgame-command:latest

FROM adoptopenjdk:11-jre-hotspot as builder
WORKDIR application
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} application.jar
RUN java -Djarmode=layertools -jar application.jar extract

FROM adoptopenjdk:11-jre-hotspot
WORKDIR application
COPY --from=builder application/dependencies/ ./
RUN true
COPY --from=builder application/snapshot-dependencies/ ./
RUN true
COPY --from=builder application/spring-boot-loader/ ./
RUN true
COPY --from=builder application/application/ ./


ENTRYPOINT ["java", "org.springframework.boot.loader.JarLauncher"]
