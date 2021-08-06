package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	// libs to handle on the fly pcaping
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// get canned payloads in memory for delivery
var ssdp_resp, _ = ioutil.ReadFile("payloads/ssdp.http")
var gatedesc_resp, _ = ioutil.ReadFile("payloads/gatedesc.xml")
var gateconnSCPD_resp, _ = ioutil.ReadFile("payloads/gateconnSCPD.xml")
var gateicfgSCPD_resp, _ = ioutil.ReadFile("payloads/gateicfgSCPD.xml")
var dummy_resp, _ = ioutil.ReadFile("payloads/dummy.xml")
var fo04_resp, _ = ioutil.ReadFile("payloads/404.html")
var getportmap_resp, _ = ioutil.ReadFile("payloads/upnp.entry.xml")
var getportmap_err_resp, _ = ioutil.ReadFile("payloads/upnp.error.xml")
var addportmap_succ_resp, _ = ioutil.ReadFile("payloads/upnp.inject.success.xml")
var addportmap_args_err_resp, _ = ioutil.ReadFile("payloads/upnp.inject.args_error.xml")
var addportmap_conflict_err_resp, _ = ioutil.ReadFile("payloads/upnp.inject.conflict_error.xml")
var delportmap_succ_resp, _ = ioutil.ReadFile("payloads/upnp.delete.success.xml")

// get regex patterns compiled for extracting XML values
var regex_inj_description = regexp.MustCompile(`NewPortMappingDescription>([\w\s\-\.+=]+)</`)
var regex_inj_duration = regexp.MustCompile(`NewLeaseDuration>([\d]+)</`)
var regex_inj_int_client = regexp.MustCompile(`NewInternalClient>([0-9\.]+)</`)
var regex_inj_enabled = regexp.MustCompile(`NewEnabled>([\d]+)</`)
var regex_inj_ext_port = regexp.MustCompile(`NewExternalPort>([\d]+)</`)
var regex_inj_rem_host = regexp.MustCompile(`NewRemoteHost>([0-9\.]+)</`)
var regex_inj_protocol = regexp.MustCompile(`NewProtocol>([\w]+)</`)
var regex_inj_int_port = regexp.MustCompile(`NewInternalPort>([\d]+)</`)
var regex_get_index = regexp.MustCompile(`NewPortMappingIndex>([\d]+)</`)

// get regex pattern compiled for ClientHello domain/host sanitization
var regex_hello_host = regexp.MustCompile(`([a-zA-Z0-9\-\.]+)`)

// our look up table of currently injected proxies
// (needed for emulating the GetGenericPortMapping functionality, in case our attackers use it)
var proxy_configs = map[int]*ProxyTemplate{}

type ProxyTemplate struct {
	Description  string // attacker provided description
	Duration     int    // duration (in seconds) that the proxy should listen
	Endpoint     string // where the proxy will send data
	EndpointPort int    // the port on the endpoint that proxy will send data to
	ProxyPort    int    // the port we'll start listening on for proxying data
	RemoteHost   string // the host doing the injection
	Enabled      int    // is this proxy enabled
	Protocol     string // TCP or UDP
}

// SSDP packet handler
func handle_ssdp(udpsock net.PacketConn) {
	for {
		buf := make([]byte, 1024)
		_, addr, err := udpsock.ReadFrom(buf)
		if err != nil {
			continue
		}
		go respond_ssdp(udpsock, addr, buf)
	}
}

// SSDP canned respone handler, direct scanner to UPnP listener...
func respond_ssdp(udpsock net.PacketConn, addr net.Addr, buf []byte) {
	log.Print("SSDP In:")
	log.Print(addr)
	log.Print(string(bytes.Trim(buf, "\x00")))
	if strings.Contains(string(buf), "M-SEARCH") {
		udpsock.WriteTo([]byte(ssdp_resp), addr)
	}
}

// UPnP connection handler
func handle_upnp(tcpsock net.Listener) {
	for {
		tcpconn, err := tcpsock.Accept()
		if err != nil {
			continue
		}
		go respond_upnp(tcpconn)
	}
}

// UPnP payload parsing and response logic
func respond_upnp(tcpconn net.Conn) {
	// default response is 404
	tcp_resp := fo04_resp

	buf := make([]byte, 2048)
	_, err := tcpconn.Read(buf)
	if err != nil {
		log.Print(err)
	}

	log.Print("UPnP In:")
	log.Print(tcpconn.RemoteAddr())
	log.Print(string(bytes.Trim(buf, "\x00")))

	// check for and respond differently for various expected paths
	if strings.Contains(string(buf), "gatedesc.xml") {
		tcp_resp = gatedesc_resp
	}
	if strings.Contains(string(buf), "dummy.xml") {
		tcp_resp = dummy_resp
	}
	if strings.Contains(string(buf), "gateconnSCPD.xml") {
		tcp_resp = gateconnSCPD_resp
	}
	if strings.Contains(string(buf), "gateicfgSCPD.xml") {
		tcp_resp = gateicfgSCPD_resp
	}

	// handle GetGenericPortMappingEntry requests
	if strings.Contains(string(buf), "GetGenericPortMappingEntry") {
		tcp_resp = getportmap_err_resp
		mapping_index := regex_get_index.FindStringSubmatch(string(buf))
		if len(mapping_index) == 2 {
			index_int, _ := strconv.Atoi(mapping_index[1])
			if proxy_conf, exists := proxy_configs[index_int]; exists {
				tcp_resp = []byte(fmt.Sprintf(string(getportmap_resp), proxy_conf.RemoteHost, proxy_conf.ProxyPort, proxy_conf.Protocol, proxy_conf.EndpointPort, proxy_conf.Endpoint, proxy_conf.Enabled, proxy_conf.Description, proxy_conf.Duration))
				tcp_resp = update_headers(tcp_resp)
			}
		}
	}

	// if we find a DeletePortMapping XML node, just respond that we deleted it
	// (this XML is usually malformed and will also trigger AddPortMapping... avoid that)
	if strings.Contains(string(buf), "DeletePortMapping") {
		tcp_resp = delportmap_succ_resp
	} else if strings.Contains(string(buf), "AddPortMapping") {
		// if we're here it's a AddPortMapping request that ISN'T malformed
		// set default response to success... we'll switch it to an error in the checks below
		tcp_resp = addportmap_succ_resp
		proxy_conf := ProxyTemplate{}

		// find fields we need to inject, store them in proxy_conf struct

		// handle description, override with default if empty
		desc := regex_inj_description.FindStringSubmatch(string(buf))
		if len(desc) == 2 {
			proxy_conf.Description = desc[1]
		} else {
			proxy_conf.Description = "miniupnpd"
		}

		// handle duration, error if empty
		dura := regex_inj_duration.FindStringSubmatch(string(buf))
		if len(dura) == 2 {
			dura_int, err := strconv.Atoi(dura[1])
			if err != nil {
				tcp_resp = addportmap_args_err_resp
			}
			proxy_conf.Duration = dura_int
		}

		// handle internal client => endpoint, error if empty
		int_client := regex_inj_int_client.FindStringSubmatch(string(buf))
		if len(int_client) == 2 {
			proxy_conf.Endpoint = int_client[1]
		} else {
			tcp_resp = addportmap_args_err_resp
		}

		// handle internal client port => endpointport, error if empty
		int_port := regex_inj_int_port.FindStringSubmatch(string(buf))
		if len(int_port) == 2 {
			endpoint_port_int, err := strconv.Atoi(int_port[1])
			if err != nil {
				tcp_resp = addportmap_args_err_resp
			}
			proxy_conf.EndpointPort = endpoint_port_int
		} else {
			tcp_resp = addportmap_args_err_resp
		}

		// handle external port => proxyport, error if empty
		ext_port := regex_inj_ext_port.FindStringSubmatch(string(buf))
		if len(ext_port) == 2 {
			proxy_port_int, err := strconv.Atoi(ext_port[1])
			if err != nil {
				tcp_resp = addportmap_args_err_resp
			}
			proxy_conf.ProxyPort = proxy_port_int
		} else {
			tcp_resp = addportmap_args_err_resp
		}

		// store the IP of the host doing the injection
		rem_host := regex_inj_rem_host.FindStringSubmatch(string(buf))
		if len(rem_host) == 2 {
			proxy_conf.RemoteHost = rem_host[1]
		}

		// handle enabled, if no set, default to 0, check for 1, if empty, error out
		enabled := regex_inj_enabled.FindStringSubmatch(string(buf))
		if len(enabled) == 2 {
			proxy_conf.Enabled = 0
			if enabled[1] == "1" {
				proxy_conf.Enabled = 1
			}
		} else {
			tcp_resp = addportmap_args_err_resp
		}

		// check protocol for TCP or UDP, error out for anything else
		protocol := regex_inj_protocol.FindStringSubmatch(string(buf))
		if len(protocol) == 2 {
			proxy_conf.Protocol = "TCP"
			if protocol[1] == "UDP" {
				proxy_conf.Protocol = "UDP"
			}
		} else {
			tcp_resp = addportmap_args_err_resp
		}

		// if we've gotten here with no errors, create the proxy
		if string(tcp_resp) == string(addportmap_succ_resp) {
			create_proxy(proxy_conf)
		}
	}

	// send our response
	tcpconn.Write([]byte(tcp_resp))
	defer tcpconn.Close()
}

// TCP Proxy functions
func run_tcp_proxy(proxy_conf ProxyTemplate) {
	// start logging traffic
	go handle_pcap(proxy_conf)

	// if we're dealing with a SSL/TLS endpoint, we'll MITM the crypto
	// this requires more work...
	if proxy_conf.EndpointPort == 443 {
		run_tls_proxy(proxy_conf)
		return
	}

	// otherwise create our plaintext proxy listener and handle incoming connections
	tcpsock, err := net.Listen("tcp4", ":"+strconv.Itoa(proxy_conf.ProxyPort))
	if err != nil {
		log.Print("error creating TCP proxy!")
		return
	}
	for {
		tcpconn, err := tcpsock.Accept()
		if err != nil {
			continue
		}
		defer tcpconn.Close()
		go handle_tcp_proxy_endpoint(tcpconn, proxy_conf)
	}
	defer tcpsock.Close()
}

// Execute the bash script responsible for fetching, copying the subject, and generating the
// new self signed certificate that we'll use to spin up the TLS connection
func clone_cert(endpoint_ip string, server_name string) {
	cert_hostname := regex_hello_host.FindStringSubmatch(server_name)
	cmd := exec.Command("/bin/bash", "-c", "./scripts/clone_cert.sh "+endpoint_ip+" "+cert_hostname[1])
	cmd.Output()
}

// TLS proxies require us to MITM the TLS connection with a passible cert
// for TLS connections we'll need to do some extra work
func run_tls_proxy(proxy_conf ProxyTemplate) {
	// we need to specially configure out TLS connection to allow us to capture the ClientHello
	// packet
	config := &tls.Config{
		GetCertificate: func(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// we have captured the ClientHello at this point...
			// now we need to fetch the endpoints associated certificate and copy
			// it's Subject line, clone it into a self-signed certificate of our own
			clone_cert(proxy_conf.Endpoint, helloInfo.ServerName)

			// load our newly created certifcate and finish setting up the TLS connection
			crt, err := tls.LoadX509KeyPair("./keys/"+proxy_conf.Endpoint+".crt", "./keys/master.key")
			if err != nil {
				log.Println(err)
				return nil, nil
			}
			return &crt, nil
		},
	}

	proxy_serv := http.NewServeMux()
	proxy_serv.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		log.Printf("%+v", proxy_conf)
		log.Printf("%+v", req)

		proxy_client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

		// can't have ReqURI set when proxying request
		req.RequestURI = ""
		req.URL.Scheme = "https"
		req.URL.Host = proxy_conf.Endpoint

		res, err := proxy_client.Do(req)
		if err != nil {
			log.Print(err)
		}
		defer res.Body.Close()

		log.Printf("%+v", res)
		io.Copy(w, res.Body)
	})

	tls_list, err := tls.Listen("tcp", ":"+strconv.Itoa(proxy_conf.ProxyPort), config)
	if err != nil {
		log.Print(err)
		return
	}
	http.Serve(tls_list, proxy_serv)
}

// handle moving data from socket to socket, capture everything in the middle
func tcp_proxy_log(to net.Conn, from net.Conn, proxy ProxyTemplate) {
	sent_buf := make([]byte, 10000)
	for {
		slen, err := from.Read(sent_buf)
		if err != nil {
			break
		}
		if slen >= 1 {
			log.Print(from.RemoteAddr().String() + "=>" + to.RemoteAddr().String())
			log.Print(proxy)
			log.Print(string(sent_buf[0:slen]))
		}
		to.Write(sent_buf[0:slen])
	}
}

// establish our connection to the endpoint for proxying traffic for this incoming connection
func handle_tcp_proxy_endpoint(tcpconn net.Conn, proxy_conf ProxyTemplate) {
	proxyconn, err := net.Dial("tcp", proxy_conf.Endpoint+":"+strconv.Itoa(proxy_conf.EndpointPort))
	if err != nil {
		log.Print("error establishing endpoint connection")
		log.Print(err)
		return
	}

	go tcp_proxy_log(proxyconn, tcpconn, proxy_conf)
	go tcp_proxy_log(tcpconn, proxyconn, proxy_conf)
}

// UDP Proxy functions
func run_udp_proxy(proxy_conf ProxyTemplate) {
	udpsock, err := net.ListenPacket("udp4", ":"+strconv.Itoa(proxy_conf.ProxyPort))
	if err != nil {
		log.Print("error creating UDP proxy")
		return
	}
	for {
		buf := make([]byte, 12048)
		_, addr, err := udpsock.ReadFrom(buf)
		if err != nil {
			continue
		}
		go udp_proxy_respond(udpsock, addr, buf, proxy_conf)
	}
}
func udp_proxy_respond(udpsock net.PacketConn, addr net.Addr, buf []byte, proxy_conf ProxyTemplate) {
	res_buf := make([]byte, 12048)
	log.Print("UDP Proxy in:")
	log.Print(addr)
	log.Print(string(bytes.Trim(buf, "\x00")))
	proxyconn, err := net.Dial("udp", proxy_conf.Endpoint+":"+strconv.Itoa(proxy_conf.EndpointPort))
	if err != nil {
		log.Print("failed to establish proxyconn to endpoint")
		return
	}
	defer proxyconn.Close()

	buf = bytes.Trim(buf, "\x00")

	proxyconn.Write(buf)
	proxyconn.Read(res_buf)

	log.Print("UDP proxy out:")
	log.Print(addr)
	log.Print(string(bytes.Trim(res_buf, "\x00")))

	udpsock.WriteTo(res_buf, addr)

}

// create a TCP/UDP proxy based on incoming injection attempt
func create_proxy(proxy_conf ProxyTemplate) {
	proxy_configs[len(proxy_configs)] = &proxy_conf
	if proxy_conf.Protocol == "TCP" {
		go run_tcp_proxy(proxy_conf)
	} else {
		go run_udp_proxy(proxy_conf)
	}
}

// update Content-Length header for variable response XML payloads
func update_headers(resp []byte) []byte {
	// we begin counting at the start of the XML payload, our payloads also
	// include HTTP headers, these need to be ignored when calculating the
	// Content-Length header
	start := strings.Index(string(resp), "<?xml")
	new_len := fmt.Sprintf("Content-Length: %d", (len(resp)-start)-1)
	result := strings.Replace(string(resp), "Content-Length: 0", new_len, 1)
	return []byte(result)
}

// create pcaps on the fly for proxy connections
func handle_pcap(proxy_conf ProxyTemplate) {
	filter := "(port " + strconv.Itoa(proxy_conf.ProxyPort) + ") or (host " + proxy_conf.Endpoint + " and port " + strconv.Itoa(proxy_conf.EndpointPort) + ")"
	//log.Print(filter)

	t := time.Now()
	ts := t.Format("2006.01.02_15.04.05_UTC")
	filename := proxy_conf.Endpoint + ":" + strconv.Itoa(proxy_conf.EndpointPort) + "_" + ts + ".pcap"
	outfile, _ := os.Create("./pcaps/" + filename)
	defer outfile.Close()

	pcaper, _ := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	pcaper.SetBPFFilter(filter)

	pcapwriter := pcapgo.NewWriter(outfile)
	pcapwriter.WriteFileHeader(1600, pcaper.LinkType())

	pcapsrc := gopacket.NewPacketSource(pcaper, pcaper.LinkType())
	for pkt := range pcapsrc.Packets() {
		pcapwriter.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
	}
}

func main() {
	// map starts @ 0, index in devices start @ 1
	// create a junk entry to push map to take incoming
	// proxy confs and store @ 1
	create_proxy(ProxyTemplate{Description: "ignore"})

	// setup UDP and TCP socks
	udpsock, err := net.ListenPacket("udp4", ":1900")
	if err != nil {
		log.Fatal(err)
	}
	defer udpsock.Close()
	tcpsock, err := net.Listen("tcp4", ":2048")
	if err != nil {
		log.Fatal(err)
	}
	defer tcpsock.Close()

	// spin up handlers for incoming packets/connections
	go handle_ssdp(udpsock)
	go handle_upnp(tcpsock)

	select {} // keep running
}
