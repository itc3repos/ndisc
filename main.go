package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var debug bool

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("usage: ndisc router community\n")
		return
	}

	if os.Getenv("DEBUG") != "" {
		debug = true
	}

	log.Printf("DEBUG=%v", debug)

	scan(os.Args[1], os.Args[1])
}

func scan(router, community string) {
	scanDescr(router, community)
}

type port struct {
	index int
	descr string
}

var tabIndex = map[int]*port{}

func scanDescr(router, community string) {

	w, errDescr := snmpwalk(router, community, "RFC1213-MIB::ifDescr")
	if errDescr != nil {
		log.Printf("snmpwalk descr: %v", errDescr)
		return
	}

	defer w.wait()

	r := bufio.NewReader(w.reader)
	for {
		str, errRead := r.ReadString('\n')
		if errRead == io.EOF {
			if str != "" {
				handleDescr(str)
			}
			break
		}
		if errRead != nil {
			log.Printf("snmpwalk read error: %v", errRead)
			break
		}
		handleDescr(str)
	}
}

func handleDescr(line string) {
	line = strings.TrimSpace(line)

	log.Printf("descr line: [%s]", line)

	prefix := "RFC1213-MIB::ifDescr."
	if !strings.HasPrefix(line, prefix) {
		return
	}

	suff := line[len(prefix):]

	i := strings.IndexByte(suff, ' ')
	if i < 0 {
		log.Printf("bad ifindex: [%s]", suff)
		return
	}

	index, err := strconv.Atoi(suff[:i])
	if err != nil {
		log.Printf("bad ifindex value: %s [%s]", err, suff)
		return
	}

	lastQ := strings.LastIndexByte(suff, '"')
	if lastQ < 0 {
		log.Printf("bad descr last quote: [%s]", suff)
		return
	}

	firstQ := strings.LastIndexByte(suff[:lastQ], '"')
	if firstQ < 0 {
		log.Printf("bad descr first quote: [%s]", suff)
		return
	}

	descr := suff[firstQ+1 : lastQ]

	p := &port{
		index: index,
		descr: descr,
	}

	tabIndex[index] = p

	log.Printf("index=%d descr=[%s]", index, descr)
}

type walk struct {
	cmd    *exec.Cmd
	reader io.Reader
	debug  bool
}

func (w *walk) wait() {
	if w.debug {
		return
	}

	err := w.cmd.Wait()
	if err != nil {
		log.Printf("wait error: %v", err)
	}
}

func snmpwalk(router, community, oid string) (*walk, error) {

	w := walk{debug: debug}

	if debug {
		buf := debugBuf(oid)
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

func debugBuf(oid string) string {

	if strings.HasPrefix(oid, "RFC1213-MIB::ifDescr") {
		return bufDescr
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
