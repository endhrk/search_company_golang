package main

import (
    "os"
    "fmt"
    "flag"
    "bufio"
    "net"
    "regexp"
    "strings"
    "./whois"
)

func isIP(ip string) bool {
    ipAddr := net.ParseIP(ip)
    if ipAddr != nil {
        return true
    }
    return false
}

func getCompanyName(ip string) (ret string) {
    if !isIP(ip) {
        return ret
    }

    lines := bufio.NewScanner(strings.NewReader(whois.Whois(ip)))
    lines.Scan()
    if strings.Contains(lines.Text(), "whois.apnic.net") {
        var reset bool
        for lines.Scan() {
            if strings.Contains(lines.Text(), "% Information related") {
                reset = true
                continue
            }
            if reset && regexp.MustCompile("^descr:").MatchString(lines.Text()) {
                ret = regexp.MustCompile("^(.*)  +(.*)$").FindStringSubmatch(lines.Text())[2]
                reset = false
                if strings.Contains(ret, "APNIC") || strings.Contains(ret, "Early registration addresses") {
                    ret = ""
                }
            }
        }
    } else {
        for lines.Scan() {
            if regexp.MustCompile("^f.").MatchString(lines.Text()) {
                ret = regexp.MustCompile("^(.*)  +(.*)$").FindStringSubmatch(lines.Text())[2]
                break
            }
        }
    }
    return ret
}

func checkError(err error) {
    if err != nil {
        panic(err)
        os.Exit(1)
    }
}

func main() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "%s [-input] [-output] [ip]\n", os.Args[0])
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "  IPaddress\n")
        fmt.Fprintf(os.Stderr, "        IP address\n")
        os.Exit(0)
    }

    in := flag.String("input", "", "input IP address list")
    out := flag.String("output", "output.csv", "output file path")
    flag.Parse()

    if len(flag.Args()) > 0 && isIP(flag.Args()[0]){
        ip := flag.Args()[0]
        fmt.Println(ip + "," + getCompanyName(ip))
    } else if *in != "" {
        inFile, err := os.Open(*in)
        checkError(err)
        defer inFile.Close()
        outFile, err := os.Create(*out)
        checkError(err)
        defer outFile.Close()

        scanner := bufio.NewScanner(inFile)
        writer := bufio.NewWriter(outFile)
        for scanner.Scan() {
            ip := scanner.Text()
            if isIP(ip) {
                name := getCompanyName(ip)
                fmt.Fprintln(writer, ip + "," + name)
                fmt.Println(ip + "," + name)
                writer.Flush()
            }
        }
        checkError(scanner.Err())
    } else {
        flag.Usage()
        os.Exit(0)
    }
}
