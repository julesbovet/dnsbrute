package main

import (
    "time"
    "github.com/miekg/dns"
)

func SendDNSQuery(client *dns.Client, msg *dns.Msg, nameserver string) (r *dns.Msg, rtt time.Duration, err error) {
    // Send DNS message m to nameserver
    r, rtt, e := client.Exchange(msg, nameserver)

    return r, rtt, e
}

func CreateNSQuery(hostname string) (*dns.Msg) {
    m := createDNSMessage()

    // Set NS Question
    qt := dns.TypeNS
    qc := uint16(dns.ClassINET)
    m.Question = make([]dns.Question, 1)
    m.Question[0] = dns.Question{dns.Fqdn(hostname), qt, qc}

    return m
}

func CreateAXFRQuery(hostname string) (*dns.Msg) {
    m := createDNSMessage()

    // Set AXFR Question
    qt := dns.TypeAXFR
    qc := uint16(dns.ClassINET)
    m.Question = make([]dns.Question, 1)
    m.Question[0] = dns.Question{dns.Fqdn(hostname), qt, qc}

    return m
}

func CreateAnyQuery(hostname string) (*dns.Msg) {
    m := createDNSMessage()

    // Set ANY (*) Question
    qt := dns.TypeANY
    qc := uint16(dns.ClassINET)
    m.Question = make([]dns.Question, 1)
    m.Question[0] = dns.Question{dns.Fqdn(hostname), qt, qc}

    return m
}

func CreateAQuery(hostname string) (*dns.Msg) {
    m := createDNSMessage()

    // Set A Question
    qt := dns.TypeA
    qc := uint16(dns.ClassINET)
    m.Question = make([]dns.Question, 1)
    m.Question[0] = dns.Question{dns.Fqdn(hostname), qt, qc}

    return m
}

func InitializeClient() (*dns.Client) {
    c := new(dns.Client)
    c.Net = "udp"

    return c
}

func InitializeTransfer() (*dns.Transfer) {
    t := new(dns.Transfer)

    return t
}

func createDNSMessage() (*dns.Msg) {
    m := new(dns.Msg)

    // Set header
    m.MsgHdr.Authoritative = false
    m.MsgHdr.AuthenticatedData = false
    m.MsgHdr.CheckingDisabled = false
    m.MsgHdr.RecursionDesired = true
    m.MsgHdr.RecursionAvailable = true
    m.MsgHdr.Response = false

    m.Opcode = dns.OpcodeQuery // 0, normal query
    m.Rcode = dns.RcodeSuccess // 0
    m.Id = dns.Id()

    return m
}