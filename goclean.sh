#!/bin/bash
# The script does automatic checking on a Go package and its sub-packages, including:
# 1. gofmt         (http://golang.org/cmd/gofmt/)
# 2. go vet        (http://golang.org/cmd/vet)
# 3. gosimple      (https://github.com/dominikh/go-simple)
# 4. unconvert     (https://github.com/mdempsky/unconvert)
# 5. ineffassign   (https://github.com/gordonklaus/ineffassign)
# 6. unused        (https://github.com/dominikh/go-tools)
# 7. race detector (http://blog.golang.org/race-detector)
# 8. test coverage (http://blog.golang.org/cover)
#
set -ex

# run tests
env GORACE="halt_on_error=1" go test -race ./...

# Make sure gometalinter is installed and $GOPATH/bin is in your path.
# $ go get -v github.com/alecthomas/gometalinter"
# $ gometalinter --install"
if [ ! -x "$(type -p gometalinter)" ]; then
  exit 1
fi

# check linters
# linters do not work with modules yet
go mod vendor
unset GO111MODULE
gometalinter --vendor --disable-all --deadline=10m \
  --enable=gofmt \
  --enable=vet \
  --enable=gosimple \
  --enable=unconvert \
  --enable=ineffassign \
  --enable=unused \
  ./...

# To submit the test coverage result to coveralls.io,
# use goveralls (https://github.com/mattn/goveralls)
# goveralls -coverprofile=profile.cov -service=travis-ci
