package main

import (
    "os"
    "fmt"
    "flag"
    "bufio"
    "strings"
    "./whois"
)

func usage () {
}

func main() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
        fmt.Fprintf(os.Stderr, "%s [-csv] [-output] [ip]\n", os.Args[0])
        flag.PrintDefaults()
        fmt.Fprintf(os.Stderr, "  IPaddress\n")
        fmt.Fprintf(os.Stderr, "        IP address\n")
        os.Exit(0)
    }
    csv := flag.String("csv", "", "input IP address list")
//    out := flag.String("output", "output.csv", "output file path")
    flag.Parse()

    if *csv == "" {
        fmt.Println(whois.Whois(flag.Args()[0]))
    } else {
        scanner := bufio.NewScanner(strings.NewReader(*csv))
        for scanner.Scan() {
            fmt.Println(scanner.Text())
        }
        if err := scanner.Err(); err != nil {
            panic(err)
        }
    }
}
