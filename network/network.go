package network

import (
	"net"
	"strings"
	"time"
	"encoding/json"
)

// Create structure of Data Packages //
type Package struct {
	Option int       // For example: GET_BALANCE, ADD_TRANSACTION
	Data string 	 // Data that get's by option's
}

// Constant variables //
const (
	ENDBYTES = "\000\005\007\001\001\007\005\000"   // Proof of end data sending
	WAITTIME = 5									// Seconds for Response from Server
	DMAXSIZE = 2 << 20 // (2 ^ 20) * 2 = 2MiB
	BUFFSIZE = 4 << 10 // (2 ^ 10) * 4 = 4KiB
)

type Listener net.Listener
type Conn net.Conn

// A function that listens for a connection from the server (node) side //
func Listen(address string, handle func(Conn, *Package)) Listener {
	splited := strings.Split(address, ":")
	if len(splited) != 2 {
		return nil
	}
	listener, error := net.Listen("tcp", "0.0.0.0:" + splited[1])
	if error != nil {
		return nil
	}
	go serve(listener, handle)
	return Listener(listener)
}

// Performs actions based on the received package option //
func Handle(option int, connect Conn, pack *Package, handle func(*Package) string) bool {
	if pack.Option != option {
		return false
	} 
	connect.Write([]byte(SerializePackage(&Package {
		Option : option,
		Data : handle(pack),
	}) + ENDBYTES))
	return true
}

// Designed to connect with the client and then read the data (handleConn) // 
func serve(listener net.Listener, handle func(Conn, *Package)) {
	defer listener.Close()
	for {
		connect, error := listener.Accept()
		if error != nil {
			break
		}
		go handleConn(connect, handle)
	}
}

func handleConn(connect net.Conn, handle func(Conn, *Package)) {
	defer connect.Close()
	pack := readPackage(connect)
	if pack == nil {
		return
	}
	handle(Conn(connect), pack)
}

// Function that Sends data //
func Send(address string, pack *Package) *Package { // Func gets User Address and Data Package. Func returns Data Package
	connect, error := net.Dial("tcp", address)      // Func creates TCP connection
	if error != nil {							// Checking errors, if finds then sending zero Address
		return nil
	}
	connect.Write([]byte(SerializePackage(pack) + ENDBYTES)) // Get package into string and add ENDBYTES. After sends Serialized Package to the Server
	var response = new(Package)
	channel := make(chan bool)
	go func() {												// Func recieve response from Server
		response = readPackage(connect)
		channel <- true
	}()
	select {
		case <- channel:									
		case <- time.After(WAITTIME * time.Second): 
	}
	return response
}

// Converts a Package structure object to a string using its converting to JSON format. //
func SerializePackage(pack *Package) string {
	jsonData, error := json.MarshalIndent(*pack, "", "\t")
	if error != nil {
		return ""
	}
	return string(jsonData)
}

// Inverse function of SerializePackage. Converts string into Package //
func DeserializePackage(data string) *Package {
	var pack Package
	error := json.Unmarshal([]byte(data), &pack)
	if error != nil {
		return nil
	}
	return &pack
}


// Reads data from the connect until it encounters a const data termination string. //
func readPackage(connect net.Conn) *Package {
	var (
		data string
		size = uint64(0)				   // To determine the impossibility of going beyond the constant maximum
		buffer = make([]byte, BUFFSIZE)    // For storage
	)
	for {
		length, error := connect.Read(buffer)
		if error != nil {
			return nil
		}
		size += uint64(length)
		if size > DMAXSIZE {
			return nil
		}
		data += string(buffer[:length])
		if strings.Contains(data, ENDBYTES) {
			data = strings.Split(data, ENDBYTES)[0]
			break
		}
	}
	return DeserializePackage(data)
}

