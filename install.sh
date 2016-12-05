#!/bin/sh

dev=$1

rev=$(git rev-parse HEAD 2>/dev/null)
if [ -z "$rev" ]; then
	echo "git rev-parse HEAD failed"
	exit 1
fi

EQ="="
go version | grep "1\.4"
if [ $? -eq 0 ]; then
	echo go 1.4
	EQ=" "
fi

if [ "$dev" != "dev" ]; then
	# update file timestamps
	find $GOPATH/src/github.com/companyzero/ttk -type f -name \*.go | xargs touch
	find $GOPATH/src/github.com/companyzero/zkc -type f -name \*.go | xargs touch
fi

echo "installing commit $rev"
go install -ldflags "-X main.appBuild$EQ$rev" -v ./...
