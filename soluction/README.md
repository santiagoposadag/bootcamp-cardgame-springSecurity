docker run --name zipkin -d -p 9411:9411 openzipkin/zipkin-slim
docker run -t -i --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
docker run --name mongodb -v /var/data:/etc/mongo  -p 27017:27017 -d mongo:3
