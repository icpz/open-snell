
FROM golang:alpine AS builder
ARG target=server
ARG version=nightly
ENV target=${target}
ENV version=${version}

RUN apk add --no-cache make git
WORKDIR /src
COPY . /src
RUN go mod download && make "VERSION=${version}" ${target} && \
    ln -s snell-${target} ./build/entrypoint


FROM scratch

COPY --from=builder /src/build /
ENTRYPOINT [ "/entrypoint" ]

