package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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

	w, errDescr := snmpwalk(router, community, "RFC1213-MIB::ifDescr")
	if errDescr != nil {
		log.Printf("snmpwalk descr: %v", errDescr)
		return
	}

	defer w.wait()

	r := bufio.NewReader(w.reader)

	for {
		str, errRead := r.ReadString('\n')
		if errRead != nil {
			log.Printf("snmpwalk read error: %v", errRead)
			break
		}
		log.Printf("snmpwalk read: [%s]", str)
	}
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
		w.reader = bufio.NewReader(bytes.NewBufferString("debug string\nfim\n"))
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
