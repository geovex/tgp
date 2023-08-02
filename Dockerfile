FROM docker.io/golang:1.20-alpine AS build
WORKDIR /app
ADD . ./
RUN go mod download && go build ./cmd/tgp

FROM docker.io/golang:1.20-alpine AS deploy
RUN apk add --no-cache gcompat
WORKDIR /app
COPY --from=build /app/tgp ./
ADD config.toml ./
# EXPOSE 6666
CMD ./tgp config.toml
