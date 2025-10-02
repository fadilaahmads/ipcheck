build:
	go build --ldflags "-s -w" -o ipcheck main.go

clean:
	rm ipcheck
