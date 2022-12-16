mvn clean package -DskipTests
docker build -t xtsofka/cardgame-proxy .
docker push xtsofka/cardgame-proxy:latest
