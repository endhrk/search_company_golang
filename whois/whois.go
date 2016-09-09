package whois

import (
    "fmt"
    "net"
    "time"
    "os"
    "io/ioutil"
    "golang.org/x/text/transform"
    "golang.org/x/text/encoding"
    "golang.org/x/text/encoding/japanese"
)

func getWhoisServer(ip net.IP) string {
    return "whois.nic.ad.jp"
}

func getWhoisCharset(ip net.IP) encoding.Encoding {
    return japanese.ISO2022JP
}

func Whois(ip string) string {
    ipAddr := net.ParseIP(ip)
    conn, err := net.Dial("tcp", getWhoisServer(ipAddr) + ":43")
    checkError(err)
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(10 * time.Second))
    fmt.Fprintf(conn, ip + "\n")
    byteArray, err := ioutil.ReadAll(transform.NewReader(conn,getWhoisCharset(ipAddr).NewDecoder()))
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
