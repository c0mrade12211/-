FROM golang:latest
WORKDIR /app
COPY . .
RUN go get -u github.com/gin-gonic/gin
RUN go get go.mongodb.org/mongo-driver/mongo
RUN go build -o main .
EXPOSE 8080
CMD ["./main"]