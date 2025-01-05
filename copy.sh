#!/bin/sh

# Copy code to routers

for F in  build.sh main.c shared_secret.h ; do
	scp $F andreevka-gw:/root/link-watcher/$F
	scp $F sfpbox:/root/link-watcher/$F
done
