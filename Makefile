BINARY = tgost

.PHONY: all build clean

all: build

build:
	go build -ldflags "-s -w" -o $(BINARY) .

clean:
	rm -f $(BINARY)
