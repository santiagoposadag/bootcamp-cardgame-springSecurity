## mvn clean package -DskipTests
## docker build -t xtsofka/cardgame-queries .
## docker run --rm -p 8081:8081 xtsofka/cardgame-queries
## docker run --rm -p 8081:8081 --network host xtsofka/cardgame-queries
## docker push xtsofka/cardgame-queries:latest


FROM openjdk:11
ARG JAR_FILE=target/*.jar
COPY ${JAR_FILE} /app.jar
ENTRYPOINT ["java","-jar","/app.jar"]
EXPOSE 8081
