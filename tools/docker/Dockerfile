# Linux arm64 test image: erl 29.1.1 + Elixir 1.20.4 + Rust 1.98.1 for Arinsal Linux builds and network OTP cases.
FROM debian:bookworm
ARG OTP=29.1.1
ARG ELIXIR=1.20.4
ARG RUST=1.98.1
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential autoconf m4 libncurses-dev libssl-dev zlib1g-dev ca-certificates curl unzip git python3 \
      clang pkg-config iproute2 procps libzstd-dev netbase libcap2-bin && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/erlang/otp/releases/download/OTP-${OTP}/otp_src_${OTP}.tar.gz | tar xz -C /tmp \
 && cd /tmp/otp_src_${OTP} && ./configure --prefix=/opt/erlang --without-javac --without-wx --without-odbc \
 && make -j6 && make install && rm -rf /tmp/otp_src_${OTP}
ENV PATH=/opt/erlang/bin:$PATH
RUN curl -fsSL -o /tmp/ex.zip https://github.com/elixir-lang/elixir/releases/download/v${ELIXIR}/elixir-otp-29.zip \
 && mkdir -p /opt/elixir && unzip -q /tmp/ex.zip -d /opt/elixir && rm /tmp/ex.zip
ENV PATH=/opt/elixir/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain ${RUST} -c rustfmt,clippy
ENV PATH=/root/.cargo/bin:$PATH
RUN cargo install cargo-nextest --locked
WORKDIR /work
# Test network: docker network create --ipv6 --subnet fd00:a51a:1::/64 arinsal-net6
