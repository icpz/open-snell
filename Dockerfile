
FROM golang:alpine AS builder
ARG target=server
ENV target=${target}

RUN apk add --no-cache make git
WORKDIR /src
COPY . /src
RUN go mod download && make ${target} && \
    ln -s snell-${target} ./build/entrypoint


FROM scratch

COPY --from=builder /src/build /
ENTRYPOINT [ "/entrypoint" ]

