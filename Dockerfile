# syntax=docker/dockerfile:1.7
#
# Runtime image. GoReleaser builds the binary on the host and copies it
# into the build context before invoking `docker build`, so this stage
# receives a prebuilt `ghactor` binary alongside LICENSE/README.md.

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

COPY ghactor /usr/local/bin/ghactor

USER nonroot

ENTRYPOINT ["/usr/local/bin/ghactor"]
CMD ["--help"]
