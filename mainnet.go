package main

import (
	"fmt"
	"time"
	"strings"
	nt "./network"
)

const (
	TO_UPPER = iota + 1    // Signals the numbering of constants. In this case numbering of constants starts with 1.
	TO_LOWER
)

const (
	ADDRESS = ":8080"
)

/*****************************************************************

The client sends two consecutive requests to the server:
first to translate the string to uppercase, and then to lowercase. 

******************************************************************/
func main() {
	var (
		response = new(nt.Package)
		msg = "Hello, World!"
	)
	go nt.Listen(ADDRESS, handleServer)
	time.Sleep(500 * time.Millisecond)
	// send "Hello, World!"
	// receive "HELLO, WORLD!"
	response = nt.Send(ADDRESS, &nt.Package {
		Option : TO_UPPER,
		Data : msg,
	})
	fmt.Println(response.Data)
	// send «HELLO, WORLD!»
	// receive «hello, world!»
	response = nt.Send(ADDRESS, &nt.Package {
		Option : TO_LOWER,
		Data : msg,
	})
	fmt.Println(response.Data)
}

func handleServer(connect nt.Conn, pack *nt.Package) {
	nt.Handle(TO_UPPER, connect, pack, handleToUpper)
	nt.Handle(TO_LOWER, connect, pack, handleToLower)
}

func handleToUpper(pack *nt.Package) string {
	return strings.ToUpper(pack.Data)
}

func handleToLower(pack *nt.Package) string {
	return strings.ToLower(pack.Data)
}