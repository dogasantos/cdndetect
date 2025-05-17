package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	targetFQDN   string
	resolverFile string
	verbose      bool
	debug        bool
)

type result struct {
	Resolver string
	IPs      []string
	Err      error
}

func init() {
	flag.StringVar(&targetFQDN, "u", "", "Target FQDN to resolve")
	flag.StringVar(&resolverFile, "r", "", "File with list of DNS resolvers (IP per line)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "d", false, "Debug scoring output")
	flag.Parse()

	if targetFQDN == "" || resolverFile == "" {
		fmt.Println("Usage: ./cdncheck -u <fqdn> -r <resolvers.txt> [-v] [-d]")
		os.Exit(1)
	}
}

func readResolvers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var resolvers []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			resolvers = append(resolvers, line)
		}
	}
	return resolvers, scanner.Err()
}

func resolveDNS(fqdn, resolver, netType string, qtype uint16) (*dns.Msg, error) {
	client := &dns.Client{
		Net:     netType,
		Timeout: 5 * time.Second,
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), qtype)

	in, _, err := client.Exchange(msg, resolver+":53")
	return in, err
}

func resolveWithResolver(fqdn, resolver string) ([]string, error) {
	resp, err := resolveDNS(fqdn, resolver, "udp", dns.TypeA)
	if err != nil || len(resp.Answer) == 0 {
		resp, err = resolveDNS(fqdn, resolver, "tcp", dns.TypeA)
	}
	if err != nil {
		return nil, err
	}

	var results []string
	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			results = append(results, rr.A.String())
		case *dns.CNAME:
			return resolveWithResolver(rr.Target, resolver)
		}
	}
	return results, nil
}

func scoreIPDiversity(responses map[string]int, total int) float64 {
	if total == 0 || len(responses) <= 1 {
		return 0
	}

	maxCount := 0
	for _, count := range responses {
		if count > maxCount {
			maxCount = count
		}
	}

	var deviationSum float64
	for _, count := range responses {
		if count == maxCount {
			continue
		}
		percent := float64(count) / float64(total)
		deviationSum += percent
	}

	if deviationSum > 1.0 {
		deviationSum = 1.0
	}
	return deviationSum
}

func scoreSubnetSpread(allIPs []string) float64 {
	subnetSet := make(map[string]struct{})
	for _, ip := range allIPs {
		if parts := strings.Split(ip, "."); len(parts) >= 2 {
			subnetSet[parts[0]+"."+parts[1]] = struct{}{}
		}
	}
	return float64(len(subnetSet)) / float64(len(allIPs))
}

func scoreTTL(fqdn string, resolver string) float64 {
	resp, err := resolveDNS(fqdn, resolver, "udp", dns.TypeA)
	if err != nil || len(resp.Answer) == 0 {
		return 0
	}
	minTTL := uint32(3600)
	for _, ans := range resp.Answer {
		if ans.Header().Ttl < minTTL {
			minTTL = ans.Header().Ttl
		}
	}
	if minTTL <= 60 {
		return 1.0
	} else if minTTL <= 300 {
		return 0.5
	}
	return 0
}

func joinIPs(ips []string) string {
	return strings.Join(ips, ",")
}

func detectCDN(results []result) string {
	ipMap := make(map[string]int)
	var allIPs []string
	total := 0
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		joined := joinIPs(r.IPs)
		ipMap[joined]++
		allIPs = append(allIPs, r.IPs...)
		total++
	}

	s1 := scoreIPDiversity(ipMap, total)
	s2 := scoreSubnetSpread(allIPs)
	s3 := 0.0
	for _, r := range results {
		if r.Err == nil {
			s3 += scoreTTL(targetFQDN, r.Resolver)
		}
	}
	if total > 0 {
		s3 /= float64(total)
	}

	// Apply weight to IP Diversity
	weightedS1 := s1 * 2

	totalScore := weightedS1 + s2 + s3

	if debug {
		fmt.Printf("[DEBUG] IP Diversity Score: %.2f\n", s1)
		fmt.Printf("[DEBUG] Subnet Spread Score: %.2f\n", s2)
		fmt.Printf("[DEBUG] TTL Score: %.2f\n", s3)
		fmt.Printf("[DEBUG] Final Score: %.2f\n", totalScore)
	}

	if totalScore >= 1.5 {
		return "CDN DETECTED"
	} else if len(ipMap) > 1 {
		return "MINOR VARIATION DETECTED"
	}
	return "NO CDN DETECTED"
}

func main() {
	resolvers, err := readResolvers(resolverFile)
	if err != nil {
		fmt.Printf("Failed to read resolvers: %v\n", err)
		os.Exit(1)
	}

	resCh := make(chan result, len(resolvers))
	sem := make(chan struct{}, 100)
	var wg sync.WaitGroup

	for _, resolver := range resolvers {
		wg.Add(1)
		sem <- struct{}{}
		go func(resolver string) {
			defer wg.Done()
			defer func() { <-sem }()
			ips, err := resolveWithResolver(targetFQDN, resolver)
			resCh <- result{Resolver: resolver, IPs: ips, Err: err}
		}(resolver)
	}

	wg.Wait()
	close(resCh)

	var results []result
	for r := range resCh {
		if verbose && r.Err == nil {
			fmt.Printf("resolver: %s / response: [%s]\n", r.Resolver, joinIPs(r.IPs))
		} else if verbose && r.Err != nil {
			fmt.Printf("resolver: %s / error: %v\n", r.Resolver, r.Err)
		}
		results = append(results, r)
	}

	fmt.Println(detectCDN(results))
}
