# Build stage
FROM golang:1.24-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o authorizer ./authorizer

# Run stage — Lambda container image
FROM public.ecr.aws/lambda/provided:al2023

COPY --from=builder /app/authorizer /var/task/authorizer

ENTRYPOINT ["/var/task/authorizer"]
