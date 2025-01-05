#!/bin/sh

# Generate shared secret for build
if [ ! -r shared_secret.h ]; then
	SS=$(dd if=/dev/urandom count=1 bs=32 status=none | base64 | tr "+/=" "123")
	echo "char shared_secret[] = \"$SS\";" > shared_secret.h
fi

# Remove previous binary
[ -x link-watcher-server ] && rm link-watcher-server
[ -x link-watcher-client ] && rm link-watcher-client

# Debug version
gcc -s -DCLIENT main.c -o link-watcher-client -lcrypto
gcc -s main.c -o link-watcher-server -lcrypto

# Production version
gcc -s -DPROD -DCLIENT main.c -o link-watcher-client-prod -lcrypto
gcc -s -DPROD main.c -o link-watcher-server-prod -lcrypto
