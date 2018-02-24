# ndisc
neighbor discovery

Install
=======

    go get -u github.com/udhos/go-ping
    go get -u github.com/udhos/ndisc
    go install github.com/udhos/ndisc

Usage
=====

    # 1.1.1.1 is the target router address
    # 'comm' is the router's SNMP read community
    ndisc 1.1.1.1 comm
