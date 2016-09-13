package whois

import (
    "fmt"
    "net"
    "time"
    "os"
    "bufio"
    "io/ioutil"
    "log"
    "bytes"
    "../resources"
    "golang.org/x/text/transform"
    "golang.org/x/text/encoding"
    "golang.org/x/text/encoding/japanese"
    "golang.org/x/text/encoding/unicode"
)

func getJpnicList(file string) (ipnets []*net.IPNet) {
    data, err := resources.Asset(file)
    if err != nil {
        log.Fatal(err)
        return ipnets
    }

    scanner := bufio.NewScanner(bytes.NewReader(data))
    for scanner.Scan() {
        cidr := scanner.Text()
        _, ipnet, err := net.ParseCIDR(cidr)
        if err != nil {
            log.Fatal(err)
            continue
        }
        ipnets = append(ipnets, ipnet)
    }
    return ipnets
}

var ipnets = getJpnicList("resources/jpnic_list")

func getWhoisServer(ip net.IP) (string, encoding.Encoding) {
    for i := range ipnets {
        if ipnets[i].Contains(ip) {
            return "whois.nic.ad.jp", japanese.ISO2022JP
        }
    }
    return "whois.apnic.net", unicode.UTF8
}

func getConnection(host string) net.Conn {
    var conn net.Conn
    var err error

    for i := 1; i<6; i++ {
        conn, err = net.Dial("tcp", host  + ":43")
        if err != nil {
            fmt.Fprintf(os.Stderr, "connection failed...retrying\n")
            time.Sleep(time.Duration(20 * i) * time.Second)
            continue
        }
        break
    }
    checkError(err)
    conn.SetDeadline(time.Now().Add(10 * time.Second))
    return conn
}

func Whois(ip string) string {
    ipAddr := net.ParseIP(ip)
    host, charset := getWhoisServer(ipAddr)
    var err error
    var byteArray []byte
    for i := 1; i<6; i++ {
        conn := getConnection(host)
        defer conn.Close()

        fmt.Fprintf(conn, ip + "\n")
        byteArray, err = ioutil.ReadAll(transform.NewReader(conn,charset.NewDecoder()))
        if err != nil {
            fmt.Fprintf(os.Stderr, "query failed...retrying\n")
            conn.Close()
            time.Sleep(time.Duration(20 * i) * time.Second)
            continue
        }
        break
    }
    checkError(err)
    contents := string(byteArray[:])
    return contents
}

func checkError(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "fatal: error: %s", err.Error())
            os.Exit(1)
    }
}

func main() {

    fmt.Println(Whois("221.249.116.206"))
    fmt.Println(Whois("221.249.116.206"))
}
