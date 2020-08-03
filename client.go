package main

import (
	"net"
	"fmt"
	utls "github.com/refraction-networking/utls"
)

func main() {
	tcp, err := net.Dial("tcp", "tls13.refraction.network:443")
	if err != nil {
		fmt.Println(err)
	}
	defer tcp.Close()

	config := utls.Config{ServerName: "tls13.refraction.network"}
	tls := utls.UClient(tcp, &config, utls.HelloChrome_72)
	tls.Handshake()

	hs := tls.HandshakeState

	fmt.Printf("unsigned char *master_secret = OPENSSL_hexstr2buf(\"%x\", NULL);\n", hs.MasterSecret)
	fmt.Printf("unsigned char *client_random = OPENSSL_hexstr2buf(\"%x\", NULL);\n", hs.Hello.Random)
	fmt.Printf("unsigned char *server_random = OPENSSL_hexstr2buf(\"%x\", NULL);\n", hs.ServerHello.Random)
	fmt.Printf("unsigned char *transcript_hash = OPENSSL_hexstr2buf(\"%x\", NULL);\n", hs.State13.Transcript.Sum([]byte{}))
	fmt.Printf("unsigned char *traffic_secret = OPENSSL_hexstr2buf(\"%x\", NULL);\n", hs.State13.TrafficSecret)


	req := []byte(`GET / HTTP/1.1
Host: tls13.refractin.network`)
	req_header := []byte{17, 03, 03, 0, byte(len(req))}
	req = append(req_header, req...)


	record, err := tls.Encrypt([]byte(req))
	if err != nil {
		fmt.Println("Something went wrong")
	}
	fmt.Printf("unsigned char *packet = OPENSSL_hexstr2buf(\"%x\", NULL);\n", record)
}
