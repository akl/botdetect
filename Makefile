VERSION=$(shell git describe --tags | sed 's/^v//')
BUILD=$(shell date +%FT%T%z)
HOST=$(shell hostname)
NAME=$(shell basename `pwd`)

all:	compile
	

compile:
	go build -tags netgo -v -a \
	  -ldflags "-s -X main.Version=$(VERSION) -X main.BuildDate=$(BUILD) -X main.BuildHost=$(HOST)" \
		./cmd/botdetect/

install:
	install -m 755 ./botdetect /usr/local/bin/
