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

var (
	mock  bool
	debug bool
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("usage: ndisc router community\n")
		return
	}

	if os.Getenv("DEBUG") != "" {
		debug = true
	}

	if os.Getenv("MOCK") != "" {
		mock = true
	}

	log.Printf("MOCK=%v", mock)

	scan(os.Args[1], os.Args[1])
}

func scan(router, community string) {
	scanLines("descr", router, community, "RFC1213-MIB::ifDescr", handleDescr)
	scanLines("alias", router, community, "IF-MIB::ifAlias", handleAlias)
}

type port struct {
	index int
	descr string
	alias string
}

var tabIndex = map[int]*port{}

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

func extractIndexString(line, prefix string) (int, string, error) {

	prefix += "."

	line = strings.TrimSpace(line)

	if debug {
		log.Printf("extract: [%s]", line)
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
