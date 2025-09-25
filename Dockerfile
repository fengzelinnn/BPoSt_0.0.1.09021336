# ---- 阶段 1: 构建 ----
# 使用最新的 Rust 镜像，确保 cargo 工具链足够新
FROM rust:latest AS builder

# 为静态编译安装 musl 工具链目标
RUN rustup target add x86_64-unknown-linux-musl

# 创建工作目录
WORKDIR /build

# 复制所有项目文件
# 注意：确保你的 .dockerignore 文件配置正确，避免复制不必要的文件
COPY . .

# 使用 musl 目标进行静态编译
# 注意：需要加上 --target 参数
RUN cargo build --release --target x86_64-unknown-linux-musl


# ---- 阶段 2: 运行 ----
# 使用你期望的、精简的最终镜像
FROM debian:bookworm-slim

# 从构建阶段复制编译好的、静态链接的二进制文件
# 注意路径的变化，因为它是在 musl 目标下生成的
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/bpst /usr/local/bin/bpst

# 设置容器的启动命令
CMD ["bpst"]