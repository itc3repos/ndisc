package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var (
	mock          bool
	debug         bool
	tabIndex      = map[int]*port{}
	tabAddr       = map[string]*port{}
	privateBlocks []*net.IPNet
)

func main() {

	if len(os.Args) != 3 {
		fmt.Printf("usage: %s router community\n", os.Args[0])
		return
	}

	debug = os.Getenv("DEBUG") != ""
	mock = os.Getenv("MOCK") != ""

	log.Printf("DEBUG=%v MOCK=%v", debug, mock)

	loadPrivate()

	scan(os.Args[1], os.Args[2])

	show()
}

func loadPrivate() {
	_, p0, _ := net.ParseCIDR("10.0.0.0/8")
	_, p1, _ := net.ParseCIDR("172.16.0.0/12")
	_, p2, _ := net.ParseCIDR("192.168.0.0/16")
	privateBlocks = []*net.IPNet{p0, p1, p2}
}

func isPrivate(n net.IPNet) bool {
	for _, p := range privateBlocks {
		if p.Contains(n.IP) {
			return true
		}
	}
	return false
}

/*
{ "data": [
{ "{#DESC}" : "STT-3947-1-1", "{#INT}" : "GigabitEthernet0/2.2777", "{#IPCL}" : "189.126.193.25" },
{ "{#DESC}" : "STT-3957-2-1", "{#INT}" : "GigabitEthernet0/1.7744", "{#IPCL}" : "189.126.139.31" },
]}
*/
func show() {
	log.Printf("RESULT:")

	for _, p := range tabIndex {
		if len(p.routeNet) > 0 {
			for _, n := range p.routeNet {
				showBlock(p.index, p.descr, p.alias, p.addr, p.mask, n)
			}
		} else {
			pIP := net.ParseIP(p.addr)
			pMask := net.IPMask(net.ParseIP(p.mask))
			block := net.IPNet{IP: pIP, Mask: pMask}
			showBlock(p.index, p.descr, p.alias, p.addr, p.mask, block)
		}
	}
}

func showBlock(index int, descr, alias, addr, mask string, block net.IPNet) {
	if block.IP == nil {
		return
	}

	// scan all addresses from block

	ones, _ := block.Mask.Size()
	hosts := (1 << (32 - uint(ones))) - 3 // skip 3 = net, first host, broadcast
	b := nextIP(block.IP, 2)              // skip net and first host
	for i := 0; i < hosts; i++ {

		if debug {
			bits, _ := block.Mask.Size()
			log.Printf("index=%d descr=[%s] alias=[%s] addr=[%s/%s] block=[%s/%d] host=%s", index, descr, alias, addr, mask, block.IP, bits, b)
		}

		b = nextIP(b, 1)
	}
}

func nextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0x000000FF)
	v2 := byte((v >> 8) & 0x000000FF)
	v1 := byte((v >> 16) & 0x000000FF)
	v0 := byte((v >> 24) & 0x000000FF)
	return net.IPv4(v0, v1, v2, v3)
}

func scan(router, community string) {
	scanLines("descr", router, community, "RFC1213-MIB::ifDescr", handleDescr)
	scanLines("alias", router, community, "IF-MIB::ifAlias", handleAlias)
	scanLines("addr", router, community, "RFC1213-MIB::ipAdEntIfIndex", handleAddr)
	scanLines("mask", router, community, "RFC1213-MIB::ipAdEntNetMask", handleMask)
	scanLines("route", router, community, "IP-FORWARD-MIB::ipCidrRouteNextHop", handleRoute)
}

type port struct {
	index    int
	descr    string
	alias    string
	addr     string
	mask     string
	routeNet []net.IPNet
}

type handleFunc func(line, prefix string)

func scanLines(label, router, community, prefix string, handler handleFunc) {

	w, errDescr := snmpwalk(router, community, prefix)
	if errDescr != nil {
		log.Printf("snmpwalk %s: %v", label, errDescr)
		return
	}

	defer w.wait()

	r := bufio.NewReader(w.reader)
	for {
		str, errRead := r.ReadString('\n')
		if errRead == io.EOF {
			if str != "" {
				handler(str, prefix)
			}
			break
		}
		if errRead != nil {
			log.Printf("snmpwalk %s read error: %v", label, errRead)
			break
		}
		handler(str, prefix)
	}
}

func handleDescr(line, prefix string) {
	index, descr, err := extractIndexString(line, prefix)
	if err != nil {
		log.Printf("handleDescr: %v", err)
		return
	}

	p, found := tabIndex[index]
	if !found {
		p = &port{
			index: index,
		}
		tabIndex[index] = p
	}

	p.descr = descr

	if debug {
		log.Printf("index=%d descr=[%s]", index, descr)
	}
}

func handleAlias(line, prefix string) {
	index, alias, err := extractIndexString(line, prefix)
	if err != nil {
		log.Printf("handleAlias: %v", err)
		return
	}

	p, found := tabIndex[index]
	if !found {
		p = &port{
			index: index,
		}
		tabIndex[index] = p
	}

	p.alias = alias

	if debug {
		log.Printf("index=%d alias=[%s]", index, alias)
	}
}

func handleAddr(line, prefix string) {
	addr, index, err := extractStringIndex(line, prefix)
	if err != nil {
		log.Printf("handleAddr: %v", err)
		return
	}

	p, found := tabIndex[index]
	if !found {
		p = &port{
			index: index,
		}
		tabIndex[index] = p
	}

	p.addr = addr

	tabAddr[addr] = p

	if debug {
		log.Printf("index=%d addr=[%s]", index, addr)
	}
}

func handleMask(line, prefix string) {
	addr, mask, err := extractAddrAddr(line, prefix)
	if err != nil {
		log.Printf("handleMask: %v", err)
		return
	}

	p, found := tabAddr[addr]
	if !found {
		log.Printf("handleMask: not found: addr=[%s]", addr)
		return
	}

	p.mask = mask

	if debug {
		log.Printf("index=%d addr=[%s] mask=[%s]", p.index, addr, mask)
	}
}

func handleRoute(line, prefix string) {
	route, next, err := extractAddrAddr(line, prefix)
	if err != nil {
		log.Printf("handleRoute: %v", err)
		return
	}

	s := strings.Split(route, ".")

	routeNet := strings.Join(s[0:4], ".")
	routeMask := strings.Join(s[4:8], ".")
	rIP := net.ParseIP(routeNet)
	rMask := net.IPMask(net.ParseIP(routeMask).To4())
	rNet := net.IPNet{IP: rIP, Mask: rMask}

	if debug {
		log.Printf("route=[%s] mask=[%s] ipmask=[%s] next=[%s]", routeNet, routeMask, rMask, next)
	}

	if isPrivate(rNet) {
		// discard private routes
		return
	}

	nh := net.ParseIP(next)

	for _, p := range tabIndex {
		pIP := net.ParseIP(p.addr)
		pMask := net.IPMask(net.ParseIP(p.mask))
		pNet := net.IPNet{IP: pIP, Mask: pMask}

		if pNet.Contains(nh) {

			p.routeNet = append(p.routeNet, rNet)
			if debug {
				log.Printf("index=%d route=[%s] mask=[%s] next=[%s]", p.index, routeNet, routeMask, next)
			}
		}
	}
}

func extractIndexString(line, prefix string) (int, string, error) {

	prefix += "."

	line = strings.TrimSpace(line)

	if debug {
		log.Printf("extractIndexString: [%s]", line)
	}

	if !strings.HasPrefix(line, prefix) {
		return -1, "", fmt.Errorf("prefix mismatch: [%s]", line)
	}

	suff := line[len(prefix):]

	i := strings.IndexByte(suff, ' ')
	if i < 0 {
		return -1, "", fmt.Errorf("bad ifindex: [%s]", suff)
	}

	index, err := strconv.Atoi(suff[:i])
	if err != nil {
		return -1, "", fmt.Errorf("bad ifindex value: %s [%s]", err, suff)
	}

	lastQ := strings.LastIndexByte(suff, '"')
	if lastQ < 0 {
		return -1, "", fmt.Errorf("bad last quote: [%s]", suff)
	}

	firstQ := strings.LastIndexByte(suff[:lastQ], '"')
	if firstQ < 0 {
		return -1, "", fmt.Errorf("bad first quote: [%s]", suff)
	}

	str := suff[firstQ+1 : lastQ]

	return index, str, nil
}

// RFC1213-MIB::ipAdEntIfIndex.192.168.208.189 = INTEGER: 31
func extractStringIndex(line, prefix string) (string, int, error) {

	prefix += "."

	line = strings.TrimSpace(line)

	if debug {
		log.Printf("extractStringIndex: [%s]", line)
	}

	if !strings.HasPrefix(line, prefix) {
		return "", -1, fmt.Errorf("prefix mismatch: [%s]", line)
	}

	suff := line[len(prefix):]

	i := strings.IndexByte(suff, ' ')
	if i < 0 {
		return "", -1, fmt.Errorf("bad ifindex: [%s]", suff)
	}

	str := suff[:i]

	lastS := strings.LastIndexByte(suff, ' ')
	if lastS < 0 {
		return "", -1, fmt.Errorf("bad last space: [%s]", suff)
	}

	index, err := strconv.Atoi(suff[lastS+1:])
	if err != nil {
		return "", -1, fmt.Errorf("bad ifindex value: %s [%s]", err, suff)
	}

	return str, index, nil
}

// RFC1213-MIB::ipAdEntNetMask.192.168.208.189 = IpAddress: 255.255.255.252
func extractAddrAddr(line, prefix string) (string, string, error) {

	prefix += "."

	line = strings.TrimSpace(line)

	if debug {
		log.Printf("extractStringIndex: [%s]", line)
	}

	if !strings.HasPrefix(line, prefix) {
		return "", "", fmt.Errorf("prefix mismatch: [%s]", line)
	}

	suff := line[len(prefix):]

	i := strings.IndexByte(suff, ' ')
	if i < 0 {
		return "", "", fmt.Errorf("bad ifindex: [%s]", suff)
	}

	addr1 := suff[:i]

	lastS := strings.LastIndexByte(suff, ' ')
	if lastS < 0 {
		return "", "", fmt.Errorf("bad last space: [%s]", suff)
	}

	addr2 := suff[lastS+1:]

	return addr1, addr2, nil
}

type walk struct {
	cmd    *exec.Cmd
	reader io.Reader
	mock   bool
}

func (w *walk) wait() {
	if w.mock {
		return
	}

	err := w.cmd.Wait()
	if err != nil {
		log.Printf("wait error: %v", err)
	}
}

func snmpwalk(router, community, oid string) (*walk, error) {

	w := walk{mock: mock}

	if mock {
		buf := mockBuf(oid)
		w.reader = bufio.NewReader(bytes.NewBufferString(buf))
		return &w, nil
	}

	w.cmd = exec.Command("snmpwalk", "-v", "2c", "-c", community, router, oid)

	stdout, errOut := w.cmd.StdoutPipe()
	if errOut != nil {
		return nil, errOut
	}

	stderr, errErr := w.cmd.StderrPipe()
	if errErr != nil {
		return nil, errErr
	}

	w.reader = io.MultiReader(stdout, stderr)

	if errStart := w.cmd.Start(); errStart != nil {
		return nil, errStart
	}

	return &w, nil
}

func mockBuf(oid string) string {

	if strings.HasPrefix(oid, "RFC1213-MIB::ifDescr") {
		return bufDescr
	}

	if strings.HasPrefix(oid, "IF-MIB::ifAlias") {
		return bufAlias
	}

	if strings.HasPrefix(oid, "RFC1213-MIB::ipAdEntIfIndex") {
		return bufAddr
	}

	if strings.HasPrefix(oid, "RFC1213-MIB::ipAdEntNetMask") {
		return bufMask
	}

	if strings.HasPrefix(oid, "IP-FORWARD-MIB::ipCidrRouteNextHop") {
		return bufRoute
	}

	return "line1\nline2\nline3\n"
}

const bufDescr = `RFC1213-MIB::ifDescr.1 = STRING: "GigabitEthernet0/1"
RFC1213-MIB::ifDescr.2 = STRING: "GigabitEthernet0/2"
RFC1213-MIB::ifDescr.3 = STRING: "GigabitEthernet0/3"
RFC1213-MIB::ifDescr.4 = STRING: "VoIP-Null0"
RFC1213-MIB::ifDescr.5 = STRING: "Null0"
RFC1213-MIB::ifDescr.6 = STRING: "Loopback0"
RFC1213-MIB::ifDescr.10 = STRING: "GigabitEthernet0/1.3487"
RFC1213-MIB::ifDescr.11 = STRING: "GigabitEthernet0/1.3488"
RFC1213-MIB::ifDescr.31 = STRING: "GigabitEthernet0/2.2777"
`

const bufAlias = `IF-MIB::ifAlias.31 = STRING: "STT-3947-1-1"
`

const bufAddr = `RFC1213-MIB::ipAdEntIfIndex.192.168.208.189 = INTEGER: 31
`

const bufMask = `RFC1213-MIB::ipAdEntNetMask.192.168.208.189 = IpAddress: 255.255.255.252
`

const bufRoute = `IP-FORWARD-MIB::ipCidrRouteNextHop.189.126.193.24.255.255.255.248.0.192.168.208.190 = IpAddress: 192.168.208.190
IP-FORWARD-MIB::ipCidrRouteNextHop.1.1.1.0.255.255.255.0.0.192.168.208.190 = IpAddress: 192.168.208.190
IP-FORWARD-MIB::ipCidrRouteNextHop.10.0.0.0.255.255.255.0.0.192.168.208.190 = IpAddress: 192.168.208.190
`
