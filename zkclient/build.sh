#!/bin/sh
rev=$(git rev-parse HEAD 2>/dev/null)
if [ -z "$rev" ]; then
        echo "git rev-parse HEAD failed"
        exit 1
fi

EQ="="
go version | grep "1\.4"
if [ $? -eq 0 ]; then
	echo using go 1.4 for ldflags
	EQ=" "
fi

echo "building commit $rev"
go build -ldflags "-X main.appBuild$EQ$rev" -v
