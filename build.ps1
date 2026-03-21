rustup target add x86_64-unknown-freebsd
rustup toolchain add stable-x86_64-unknown-linux-gnu --profile minimal --force-non-host
cargo install cross
cross build --release --target x86_64-unknown-freebsd
