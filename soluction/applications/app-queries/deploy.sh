mvn clean package -DskipTests
docker build -t xtsofka/cardgame-queries .
docker push xtsofka/cardgame-queries:latest
