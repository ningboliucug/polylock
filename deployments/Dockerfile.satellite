FROM golang:alpine

# 安装 tc 工具
RUN apk add --no-cache iproute2

WORKDIR /app

# 【关键修改】：配置国内 Go 代理，解决下载超时问题
ENV GOPROXY=https://goproxy.cn,direct

# 优化编译速度：先单独拷贝 go.mod 和 go.sum 下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 拷贝剩余所有源码并编译
COPY . .
RUN go build -o sat_app .
