## npm run build
## docker build -t xtsofka/cardgame-web .
## docker run --rm -p 80:80 xtsofka/cardgame-web
## docker run -d -it -p 80:80 xtsofka/cardgame-web
## docker run --rm -p 80:80 --network host xtsofka/cardgame-web
## docker push xtsofka/cardgame-web:latest


FROM nginx:1.23-alpine
COPY ./dist/web /usr/share/nginx/html
