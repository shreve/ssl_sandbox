package main

import (
	"net"
	"fmt"
	utls "github.com/refraction-networking/utls"
)

// Export for use in forge.c
func export(name string, val interface{}) {
	fmt.Printf("bytes %s = hex2bytes(\"%x\");\n", name, val)
}

func testClient(tls *utls.UConn) {
	request := []byte(`GET / HTTP/1.1
Host: tls13.refraction.network
Accept: text/html

`)

	fmt.Println(string(request))
	tls.Write(request)
	buf := make([]byte, 512)
	tls.Read(buf)
	fmt.Println(string(buf))
}

func main() {
	server := "tls13.refraction.network"
	tcp, err := net.Dial("tcp", fmt.Sprintf("%s:443", server))
	if err != nil {
		fmt.Println(err)
	}
	defer tcp.Close()

	config := utls.Config{ServerName: server}
	tls := utls.UClient(tcp, &config, utls.HelloChrome_72)
	tls.Handshake()
	defer tls.Close()

	// testClient(tls)


	// hs := tls.HandshakeState

	// export("ciphersuite", hs.State13.Suite)
	// export("master_secret", hs.MasterSecret)
	// export("client_random", hs.Hello.Random)
	// export("server_random", hs.ServerHello.Random)
	// export("transcript_hash", hs.State13.Transcript.Sum([]byte{}))
	export("traffic_secret", tls.Secret())

	// Generate the byte sequence from the spec example
	payload := make([]byte, 50)
	for i := 0; i < 50; i++ {
		payload[i] = byte(i)
	}

	// Add TLS header. Length will be added by encryption function
	rec_header := []byte{0x17, 0x03, 0x03, 0, 0}
	rec := append(rec_header, payload...)

	record, err := tls.Encrypt([]byte(rec))
	if err != nil {
		fmt.Println("Something went wrong")
	}
	export("packet", record)
}

// To run, this script requires the following methods in uTLS u_conn.go
//
// func (u UConn) Encrypt(payload []byte) ([]byte, error) {
// 	return u.out.encrypt([]byte{}, payload, u.config.rand())
// }
//
// func (u UConn) Secret() []byte {
// 	if len(u.HandshakeState.State13.TrafficSecret) > 0 {
// 		return u.HandshakeState.State13.TrafficSecret
// 	} else {
// 		return u.in.trafficSecret
// 	}
// }
