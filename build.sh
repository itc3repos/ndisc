#!/bin/sh

gobin=~/go/bin

gofmt -s -w *.go
go tool fix *.go
go tool vet .

[ -x $gobin/gosimple ] && $gobin/gosimple *.go
[ -x $gobin/golint ] && $gobin/golint *.go
[ -x $gobin/staticcheck ] && $gobin/staticcheck *.go

go test github.com/udhos/ndisc
go install -v github.com/udhos/ndisc
