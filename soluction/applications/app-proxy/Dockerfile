## mvn clean package -DskipTests
## docker build -t xtsofka/cardgame-proxy .
## docker run --rm -p 8081:8081 xtsofka/cardgame-proxy
## docker run --rm -p 8081:8081 --network host xtsofka/cardgame-proxy
## docker push xtsofka/cardgame-proxy:latest

FROM openjdk:11
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} /app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
EXPOSE 8082
