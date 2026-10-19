#
# 多阶段构建：构建阶段包含完整 Go 工具链，运行阶段使用 scratch。
# 最终镜像只包含静态链接的二进制与规则文件，无 shell、无包管理器、无 C 库，
# 既缩小攻击面，也避免基础镜像漏洞进入生产环境。
#
# 依赖已 vendor 到仓库中，构建阶段无需访问 Go module proxy，可在离线环境复现。
FROM golang:1.26-alpine AS build

WORKDIR /src

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=vendor

# 先复制依赖清单与 vendor，再复制源码，最大化利用 Docker 层缓存。
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
COPY rules ./rules
COPY testdata ./testdata

ARG VERSION=1.0.0
ARG TARGETOS=linux
ARG TARGETARCH

# 纯静态、去除构建机路径、去除符号表。
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/server ./cmd/server && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/client ./cmd/client

# ---------------- server ----------------
FROM scratch AS server

# 65532 为 distroless 约定的非 root UID；compose 中再次显式声明。
COPY --from=build /out/server /server
COPY --from=build /src/rules /app/rules

USER 65532:65532
EXPOSE 8080

# scratch 中没有 curl/wget，健康检查复用二进制自身的 -healthcheck 子命令。
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
    CMD ["/server", "-healthcheck", "-healthcheck-url", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/server"]

# ---------------- client ----------------
FROM scratch AS client

COPY --from=build /out/client /client
COPY --from=build /src/testdata /data

USER 65532:65532

ENTRYPOINT ["/client"]
CMD ["-in=/data/input.json", "-server=http://server:8080"]
