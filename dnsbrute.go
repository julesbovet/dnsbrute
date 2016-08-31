package main

import (
    "os"
    "log"
    "bufio"

    "github.com/urfave/cli"
    "strings"
    "sync"
    "github.com/miekg/dns"
    "net"
    "strconv"
)

var (
    // Command line flags
    subdomainsFile      string
    resolversFile       string
    targetsFile         string
    queryType           string
    outputFile          string
    isDebug             bool

    // Shared variables
    subdomains          = &[]string{}   // The subdomains list
    userResolvers       = &[]string{}   // The user's resolvers list
    defaultResolvers    = &[]string{}   // The default resolvers list

    nbWorker            int         // The number of parallel workers
)

const (
    numWorker int = 8
)

type DNSTarget struct {
    name        string              // The domain name
    queryType   string              // The DNS query type (default: A)
    pos         int                 // Position in resolvers array (round robin resolver selection)
    result      map[string]string   // The result map (subdomain.domain -> ip)
    mutex       *sync.Mutex         // Mutex to synchronize critical operations
}


func printDebug(str string) {
    if isDebug == true {
        log.Println("[DEBUG] " + str)
    }
}

func readLinesFromFile(path string) ([]string, error) {
    printDebug("[readLinesFromFile] Loading " + path)

    file, err := os.Open(path)

    if err != nil {
        return nil, err
    }

    defer file.Close()

    scanner := bufio.NewScanner(file)

    var lines []string
    for scanner.Scan() {
        lines = append(lines, scanner.Text())
    }

    printDebug("[readLinesFromFile] Loaded " + strconv.Itoa(len(lines)) + " subdomains")
    return lines, scanner.Err()
}


// Main method used to check for subdomains given a single domain and his associated TargetState
func (target *DNSTarget) run() {
    printDebug("[runTarget] Begun scanning " + target.name)

    var authoritativeServers []string
    var err error

    // Using default resolvers
    if len(*userResolvers) == 0 {
        // Get authoritative servers
        authoritativeServers, err = target.getAuthoritative()
        if err != nil {
            log.Fatal(err)
        }
        printDebug("[runTarget] Using authoritative servers " + strings.Join(authoritativeServers, ", ") + " as resolvers")

        // Check AXFR (zone transfer) if possible
        for _, server := range authoritativeServers {
            t := InitializeTransfer()
            msg := CreateAXFRQuery(server)
            env, err := t.In(msg, (*defaultResolvers)[0])
            if err != nil {
                continue
            }
            envelope := 0
            record := 0
            for e := range env {
                if e.Error != nil {
                    // Nothing
                }
                for _, r := range e.RR {
                    log.Printf("%s\n", r)
                }
                record += len(e.RR)
                envelope++
            }

            if record != 0 {
                log.Printf("\n;; xfr size: %d records (envelopes %d)\n", record, envelope)
                return
            }
        }

        userResolvers = &authoritativeServers
    }

    // Create channels used to communicate with subdomainWorker goroutines
    jobs := make(chan string)
    results := make(chan [2]string)

    // Start goroutines
    for i := 0; i < numWorker; i++ {
        go target.subdomainWorker(i, jobs, results)
    }

    // Send subdomains to check
    go func() {
        for _, domain := range *subdomains {
            jobs <- domain
        }
        close(jobs)
        printDebug("[runTarget] Closed job channel")
    }()

    // Check result for every subdomain
    for j := 0; j < len(*subdomains); j++ {
        res := <- results
        // Result is not empty, we found a valid subdomain
        if res[1] != "" {
            go target.parseAndAddResult(res[0], res[1])
        }
    }
    close(results)

    printDebug("[runTarget] Finished scanning " + target.name)

    // Finished scanning for subdomains, print results
    target.printResults()
}

// TODO: Use userResolvers first
// TODO: If a resolver does not work, delete it from the list and push back the domain to the domains channel
// SubdomainWorker is a goroutine used by the RunTarget method
// `numWorker` goroutines are started in parallel
// Each goroutine receives subdomains to check and return the result in a dedicated channel
func (target *DNSTarget) subdomainWorker(id int, domains <-chan string, results chan<- [2]string) {
    client := InitializeClient()
    nb_resolvers := len(*defaultResolvers)

    // Receive domains to check from the "domains" channel
    for domain := range domains {
        // Create type "A" query
        full_domain := domain + "." + target.name
        msg := CreateAQuery(full_domain)

        // Chose resolver form our resolver list
        target.mutex.Lock()
        resolver_nb := target.pos % nb_resolvers
        target.pos++
        target.mutex.Unlock()

        // Send DNS request "msg" to resolver
        printDebug("[subdomainWorker " + strconv.Itoa(id) + "] Testing domain " + full_domain + " with resolver " + (*userResolvers)[resolver_nb])
        r, _, err := SendDNSQuery(client, msg, (*defaultResolvers)[resolver_nb])
        if err != nil {
            log.Println(err)
        }
        // DNS request is succesful
        if err == nil && r.Id == msg.Id {
            // There is an answer, subdomain exists
            if len(r.Answer) > 0 {
                rrr := ""
                for _, rr := range r.Answer {
                    rrr += rr.String() + "|" // Pack answers in a single string, delimited by '|'
                }
                results <- [2]string{domain, rrr}
            } else { // No answer, subdomain does not exist
                results <- [2]string{domain, ""}
            }
        }
    }
    printDebug("[subdomainWorker " + strconv.Itoa(id) + "] Finished")
}

// ParseAndAddResult adds valid subdomains to the result map (state.result) and
// logs the subdomain along with the associated IP
func (target *DNSTarget) parseAndAddResult(domain string, result string) {
    // Records were packed in a single string delimited by the caracter '|'
    // Hence we need to split the string
    arr := strings.Split(result, "|")
    full_domain := domain + "." + target.name

    // Make sure we don't already have the result
    target.mutex.Lock()
    ip := target.result[full_domain]
    if ip != "" {
        target.mutex.Unlock()
        return
    }

    // Goto statement allows us to break out of the outer `for` loop when we're
    // in the inner `for` loop
    Loop:
    for _, record := range arr {
        // A record looks like "www.your.domain.   6828	  IN	A	XXX.XX.XXX.XXX"
        // We need to split it with the tab caracter '\t'
        linerec := strings.Split(record, "\t")
        for pos, str := range linerec {
            if str == "CNAME" {
                // Remove last '.' from the domain
                cname := linerec[pos + 1]
                if cname[len(cname) - 1] == '.' {
                    cname = cname[:len(cname) - 1]
                }
                // Record is of type CNAME. Need to check if we already have the alias' IP in our result map
                ip := target.result[cname]
                target.result[full_domain] = ip
                log.Println(full_domain + "\t" + ip)
                break Loop
            } else if str == "A" { // Record is of type A. Just grab the IP
                ip := linerec[pos + 1]
                target.result[full_domain] = ip
                log.Println(full_domain + "\t" + ip)
                break Loop
            }
        }
    }

    target.mutex.Unlock()
}

func getDefaultNameservers(name string) {
    nameservers := []string{"8.8.8.8:53", "8.8.4.4:53", "127.0.1.1:53", "127.0.0.1:53"}
    result := []string{}

    client := InitializeClient()
    msg := CreateAnyQuery(name)

    for _, server := range nameservers {
        r, _, e := SendDNSQuery(client, msg, server)
        if e == nil && r.Id == msg.Id {
            result = append(result, server)
        }
    }

    if len(result) == 0 {
        conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
        if err != nil {
            log.Fatal(err)
        }
        for _, ns := range conf.Servers {
            // if the nameserver is from /etc/resolv.conf the [ and ] are already
            // added, thereby breaking net.ParseIP. Check for this and don't
            // fully qualify such a name
            if ns[0] == '[' && ns[len(ns) - 1] == ']' {
                ns = ns[1 : len(ns) - 1]
            }
            if i := net.ParseIP(ns); i != nil {
                ns = net.JoinHostPort(ns, "53")
            } else {
                ns = dns.Fqdn(ns) + ":" + "53"
            }
            result = append(result, ns)
        }
    }

    if len(result) == 0 {
        printDebug("[getDefaultNameservers] Could not find default resolvers. Abort")
        os.Exit(42)
    }

    printDebug("[getDefaultNameservers] Selected resolvers " + strings.Join(result, ", "))

    defaultResolvers = &result
}

// GetAuthoritative returns the authoritative DNS servers for the targeted domain
func (target *DNSTarget) getAuthoritative() ([]string, error) {
    printDebug("[getAuthoritative] " + target.name)

    var servers []string

    client := InitializeClient()
    msg := CreateNSQuery(target.name)
    r, _, e := SendDNSQuery(client, msg, (*defaultResolvers)[0])

    if e != nil {
        log.Fatal("Error %s\n", e.Error())
    }
    if r.Id != msg.Id {
        log.Fatal("Id mismatch\n")
    }

    for _, rr := range r.Answer {
        length := len(rr.String())
        spaceLastIndex := strings.LastIndex(rr.String(), "\t") + 1
        tmp := rr.String()[spaceLastIndex:length] + ":53"
        servers = append(servers, tmp)
    }

    return servers, nil
}

func (target *DNSTarget) getTargetIP() {
    client := InitializeClient()
    msg := CreateAnyQuery(target.name)

    r, _, e := SendDNSQuery(client, msg, (*defaultResolvers)[0])

    if e == nil && r.Id == msg.Id {
        for _, rr := range r.Answer {
            if rr.Header().Rrtype == 1 {
                // "A" Record
                ip := strings.Split(rr.String(), "\t")[4]
                target.result[target.name] = ip
                break
            }
        }
    }
}

// Print results from a TargetState
func (target *DNSTarget) printResults() {
    log.Println(target.name + " - Found " + strconv.Itoa(len(target.result)) + " result(s):")

    for key, value := range target.result {
        log.Printf("\t%-30s %s\n", key, value)
    }
}


func runDnsBrute(c *cli.Context) error {
    var targets []string
    var err error

    // Check if we have at least one target
    if len(c.Args()) < 1 && targetsFile == "" {
        log.Fatal("You must provide a target. Use -h for help.")
    }

    // Load targets from file or from the command line arguments
    if targetsFile != "" {
        printDebug("[runDnsBrute] Reading targets from " + targetsFile)
        targets, err = readLinesFromFile(targetsFile)
        if err != nil {
            log.Fatal(err)
        }
        if len(targets) <= 0 {
            log.Fatal("Empty target file " + targetsFile)
        }
    } else {
        printDebug("[runDnsBrute] Reading targets from args: " + strings.Join(c.Args(), " "))
        targets = c.Args()
    }

    // Log to outputFile or stdout
    if outputFile == "" {
        printDebug("[runDnsBrute] Log set to stdout")
        log.SetOutput(os.Stdout)
    } else {
        printDebug("[runDnsBrute] Log set to " + outputFile)
        file, err := os.Open(outputFile)
        if err != nil {
            log.Fatal(err)
        }
        log.SetOutput(file)
    }

    // Reading all subdomains from file
    printDebug("[runDnsBrute] Reading subdomains from " + subdomainsFile)
    *subdomains, err = readLinesFromFile(subdomainsFile)
    if err != nil {
        log.Fatal(err)
    }

    // Reading all resolvers from file
    if resolversFile != "" {
        printDebug("[runDnsBrute] Reading resolvers from " + resolversFile)
        *userResolvers, err = readLinesFromFile(resolversFile)
        if err != nil {
            log.Fatal(err)
        }
    } else {
        printDebug("[runDnsBrute] Will use default resolvers because no resolver file was given")
    }

    getDefaultNameservers(targets[0])

    // WaitGroup to wait for goroutines to finish
    var waitGroup sync.WaitGroup
    waitGroup.Add(len(targets))

    // Start a goroutine for each target
    for _, name := range targets {
        go func(name string,) {
            target := DNSTarget{name, queryType, 0, make(map[string]string), &sync.Mutex{}}
            target.getTargetIP()
            target.run()
            waitGroup.Done()
        }(name)
    }

    // Wait goroutines
    waitGroup.Wait()

    return nil
}

// Func main()
// Parse flags and call function runDnsBrute
func main() {
    app := cli.NewApp()
    app.Name = "dnsbrute"
    app.Usage = "Fast enumeration of subdomains"
    app.Version = "0.0.1"
    app.Authors = []cli.Author{
        cli.Author{
            Name:  "Jules Bovet",
            Email: "jules.bovet@gmail.com",
        },
    }

    app.Flags = []cli.Flag {
        cli.StringFlag{
            Name:        "subdomains, s",
            Value:       "names.txt",
            Usage:       "A `file` containing a list of subdomains to test",
            Destination: &subdomainsFile,
        },
        cli.StringFlag{
            Name:        "resolvers, r",
            Usage:       "A `file` containing a list of DNS resolvers to use",
            Destination: &resolversFile,
        },
        cli.StringFlag{
            Name:        "targets, t",
            Usage:       "A `file` containing a list of targets",
            Destination: &targetsFile,
        },
        cli.StringFlag{
            Name:        "query-type, q",
            Value:       "A",
            Usage:       "Print all reponses for an arbitrary DNS record `type`",
            Destination: &queryType,
        },
        cli.StringFlag{
            Name:        "output, o",
            Usage:       "Output to `file`",
            Destination: &outputFile,
        },
        cli.BoolFlag{
            Name:        "debug, d",
            Usage:       "Print debug information",
            Destination: &isDebug,
        },
    }

    app.Action = runDnsBrute

    app.Run(os.Args)
}