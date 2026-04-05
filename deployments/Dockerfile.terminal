FROM golang:alpine

# 安装 tc 工具，用于模拟网络延迟
RUN apk add --no-cache iproute2

WORKDIR /app

# 配置国内 Go 代理，解决依赖下载超时问题
ENV GOPROXY=https://goproxy.cn,direct

# 优化编译速度：先拷贝模块文件下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 拷贝剩余源码并编译
COPY . .
RUN go build -o term_app .
