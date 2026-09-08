#!/usr/bin/env bash
# Run from the repository root with a GraalVM JDK and Clojure CLI on PATH.
set -euo pipefail
mkdir -p target/native-rng
clojure -M:test -e "(binding [*compile-path* \"target/native-rng\"] (compile 'native-image-random)) (shutdown-agents)"
native-image -O0 --no-fallback --initialize-at-build-time -J-Xmx3g \
  -cp "target/native-rng:$(clojure -Spath)" native_image_random target/native-rng-check
first=$(./target/native-rng-check)
second=$(./target/native-rng-check)
[[ "$first" =~ ^[0-9a-f]{64}$ && "$second" =~ ^[0-9a-f]{64}$ && "$first" != "$second" ]]
echo 'PASS native runtime RNG initialization and independent-process draws'
