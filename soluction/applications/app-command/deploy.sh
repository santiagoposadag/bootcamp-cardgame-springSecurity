mvn clean package -DskipTests
docker build -t xtsofka/cardgame-command .
docker push xtsofka/cardgame-command:latest
