package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
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

var knownCDNHostnames = []string{
	"cloudfront.net",
	"amazonaws.com",
	"akamai.net",
	"akamaiedge.net",
	"akamaitechnologies.com",
	"akadns.net",
	"edgekey.net",
	"edgesuite.net",
	"llnwd.net",
	"limelight.com",
	"limelightcdn.com",
	"fastly.net",
	"fastlylb.net",
	"cdn.cloudflare.net",
	"cloudflare.net",
	"azureedge.net",
	"vo.msecnd.net",
	"azioncdn.net",
	"azioncdn.com",
	"highwinds.com",
	"hwcdn.net",
	"cdngc.net",
	"cachefly.net",
	"cdn77.org",
	"cdn77.net",
	"stackpathdns.com",
	"stackpathcdn.com",
	"b-cdn.net",
	"bunnycdn.com",
	"edgecastcdn.net",
	"cdn.sfr.net",
	"revcn.net",
	"voxcdn.net",
	"panthercdn.com",
	"mirror-image.net",
	"cdnetworks.net",
	"cdnetworks.com",
	"bitgravity.com",
	"zenedge.net",
	"impervadosecuredns.net",
	"incapdns.net",
	"onappcdn.com",
	"resrc.it",
	"cdnsun.net",
	"cdnvideo.ru",
	"cdnlion.com",
	"quantil.cn",
	"quantil.com",
	"twimg.com",
	"twittercdn.com",
	"tencent-cloud.net",
	"alicdn.com",
	"cdnpure.com",
}

func init() {
	flag.StringVar(&targetFQDN, "u", "", "Target FQDN to resolve")
	flag.StringVar(&resolverFile, "r", "", "File with list of DNS resolvers (IP per line)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "d", false, "Debug scoring output")
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

func scoreTTL(fqdn, resolver string) float64 {
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

func scoreTTLDecay(fqdn, resolver string) float64 {
	const checks = 10
	const decayThreshold = 0.5

	var ttls []uint32
	for i := 0; i < checks; i++ {
		resp, err := resolveDNS(fqdn, resolver, "udp", dns.TypeA)
		if err != nil || len(resp.Answer) == 0 {
			continue
		}
		for _, ans := range resp.Answer {
			ttl := ans.Header().Ttl
			if ttl > 0 {
				ttls = append(ttls, ttl)
			}
		}
		time.Sleep(1 * time.Second)
	}

	if len(ttls) < 2 {
		return 0
	}

	initial := ttls[0]
	final := ttls[len(ttls)-1]

	if final >= initial || initial == 0 {
		return 0
	}

	decay := float64(initial-final) / float64(initial)
	if decay >= decayThreshold {
		return 1.0
	} else if decay >= 0.25 {
		return 0.5
	}
	return 0
}

func scoreCDNHostname(fqdn string, resolver string) float64 {
	// Check if it's a CNAME pointing to a known CDN
	resp, err := resolveDNS(fqdn, resolver, "udp", dns.TypeA)
	if err != nil || resp == nil {
		return 0
	}

	for _, ans := range resp.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			for _, cdn := range knownCDNHostnames {
				if strings.Contains(strings.ToLower(cname.Target), cdn) {
					return 1.0
				}
			}
		}
	}

	// If it's not a CNAME, resolve IPs and try PTR (reverse DNS)
	var ipList []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ipList = append(ipList, a.A.String())
		}
	}

	for _, ip := range ipList {
		ptr, err := net.LookupAddr(ip)
		if err == nil {
			for _, entry := range ptr {
				for _, cdn := range knownCDNHostnames {
					if strings.Contains(strings.ToLower(entry), cdn) {
						return 1.0
					}
				}
			}
		}
	}

	return 0
}

func scoreSameSubnetIPRotation(fqdn, resolver string) float64 {
	const checks = 10
	var allCombinations []map[string]struct{}
	allIPsFlat := make(map[string]struct{})

	for i := 0; i < checks; i++ {
		resp, err := resolveDNS(fqdn, resolver, "udp", dns.TypeA)
		if err != nil || resp == nil || len(resp.Answer) == 0 {
			continue
		}
		ipSet := make(map[string]struct{})
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ip := a.A.String()
				ipSet[ip] = struct{}{}
				allIPsFlat[ip] = struct{}{}
			}
		}
		allCombinations = append(allCombinations, ipSet)
		time.Sleep(500 * time.Millisecond)
	}

	if len(allCombinations) < 2 {
		return 0
	}

	// Check for variation
	combos := make(map[string]struct{})
	for _, combo := range allCombinations {
		keys := make([]string, 0, len(combo))
		for ip := range combo {
			keys = append(keys, ip)
		}
		sort.Strings(keys)
		joined := strings.Join(keys, ",")
		combos[joined] = struct{}{}
	}

	if len(combos) < 2 {
		return 0 // no rotation
	}

	// Check if all IPs are in the same /24 or /16
	subnetSet := make(map[string]struct{})
	for ip := range allIPsFlat {
		parts := strings.Split(ip, ".")
		if len(parts) < 4 {
			continue
		}
		subnet := parts[0] + "." + parts[1] + "." + parts[2] // /24
		subnetSet[subnet] = struct{}{}
	}

	if len(subnetSet) == 1 {
		return 1.0 // IPs rotated and all belong to same /24
	} else if len(subnetSet) <= 2 {
		return 0.5 // same /16 likely, still plausible
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

	var selectedResolver string

	for _, r := range results {
		if r.Err != nil {
			continue
		}
		joined := joinIPs(r.IPs)
		ipMap[joined]++
		allIPs = append(allIPs, r.IPs...)
		total++

		if selectedResolver == "" {
			selectedResolver = r.Resolver // pick the first successful resolver
		}
	}

	// Heuristic 1: IP Diversity
	s1 := scoreIPDiversity(ipMap, total)

	// Heuristic 2: Subnet Spread
	s2 := scoreSubnetSpread(allIPs)

	// Heuristic 3: TTL (single resolver)
	s3 := 0.0
	if selectedResolver != "" {
		s3 = scoreTTL(targetFQDN, selectedResolver)
	}

	// Heuristic 4: TTL Decay (10 checks on one resolver)
	s4 := 0.0
	if selectedResolver != "" {
		s4 = scoreTTLDecay(targetFQDN, selectedResolver)
	}

	// Heuristic 5: CNAME or PTR points to known CDN
	s5 := 0.0
	if selectedResolver != "" {
		s5 = scoreCDNHostname(targetFQDN, selectedResolver)
	}

	// Weighted total
	weightedS1 := s1 * 2
	totalScore := weightedS1 + s2 + s3 + s4 + s5

	if debug {
		fmt.Printf("[DEBUG] IP Diversity Score: %.2f\n", s1)
		fmt.Printf("[DEBUG] Subnet Spread Score: %.2f\n", s2)
		fmt.Printf("[DEBUG] TTL Score: %.2f\n", s3)
		fmt.Printf("[DEBUG] TTL Decay Score: %.2f\n", s4)
		fmt.Printf("[DEBUG] CDN CNAME/PTR Score: %.2f\n", s5)
		fmt.Printf("[DEBUG] Final Score: %.2f\n", totalScore)
	}

	if totalScore >= 1.5 {
		return "CDN DETECTED"
	} else if len(ipMap) > 1 {
		return "MINOR VARIATION DETECTED"
	}
	return "NO CDN DETECTED"
}

func detectLoadBalancer(fqdn, resolver string) string {
	const checks = 10
	var allAnswers [][]string
	var ttlSequences [][]uint32
	var ttlSetCounts = make(map[uint32]int)
	var ipSet = make(map[string]struct{})
	var subnetSet = make(map[string]struct{})

	for i := 0; i < checks; i++ {
		resp, err := resolveDNS(fqdn, resolver, "udp", dns.TypeA)
		if err != nil || resp == nil || len(resp.Answer) == 0 {
			continue
		}

		var currentIPs []string
		var currentTTLs []uint32

		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ip := a.A.String()
				currentIPs = append(currentIPs, ip)
				currentTTLs = append(currentTTLs, a.Hdr.Ttl)

				ipSet[ip] = struct{}{}
				parts := strings.Split(ip, ".")
				if len(parts) >= 3 {
					subnet := parts[0] + "." + parts[1] + "." + parts[2]
					subnetSet[subnet] = struct{}{}
				}
				ttlSetCounts[a.Hdr.Ttl]++
			}
		}

		sort.Strings(currentIPs)
		allAnswers = append(allAnswers, currentIPs)
		ttlSequences = append(ttlSequences, currentTTLs)
		time.Sleep(500 * time.Millisecond)
	}

	// Heuristic 1: IP rotation within same subnet
	sameSubnetRotation := len(ipSet) > 1 && len(subnetSet) == 1

	// Heuristic 2: Shuffled answer order
	ipOrders := make(map[string]struct{})
	for _, combo := range allAnswers {
		ipOrders[strings.Join(combo, ",")] = struct{}{}
	}
	orderShuffling := len(ipOrders) > 1

	// Heuristic 3: Equal TTLs for multiple IPs
	equalTTLs := false
	for ttl, count := range ttlSetCounts {
		if count >= 2 && ttl <= 300 {
			equalTTLs = true
			break
		}
	}

	// Heuristic 4: Non-monotonic TTL sequences
	nonMonotonic := false
	for _, seq := range ttlSequences {
		for i := 1; i < len(seq); i++ {
			if seq[i] > seq[i-1] {
				nonMonotonic = true
				break
			}
		}
		if nonMonotonic {
			break
		}
	}

	// Log debug info
	if debug {
		fmt.Printf("[DEBUG][LB] Same-subnet IP rotation: %v\n", sameSubnetRotation)
		fmt.Printf("[DEBUG][LB] IP order shuffling: %v\n", orderShuffling)
		fmt.Printf("[DEBUG][LB] Equal TTLs for multiple IPs: %v\n", equalTTLs)
		fmt.Printf("[DEBUG][LB] Non-monotonic TTLs: %v\n", nonMonotonic)
	}

	// Scoring logic
	score := 0
	if sameSubnetRotation {
		score++
	}
	if orderShuffling {
		score++
	}
	if equalTTLs {
		score++
	}
	if nonMonotonic {
		score++
	}

	switch {
	case score >= 3:
		return "LOAD BALANCER DETECTED"
	case score == 2:
		return "POSSIBLE LOAD BALANCER"
	default:
		return "NO LOAD BALANCER DETECTED"
	}
}

func main() {
	// Parse CLI flags
	flag.Parse()

	if targetFQDN == "" || resolverFile == "" {
		fmt.Println("Usage: ./cdncheck -u <fqdn> -r <resolvers.txt> [-v] [-d]")
		os.Exit(1)
	}

	// Read resolvers
	resolvers, err := readResolvers(resolverFile)
	if err != nil {
		fmt.Printf("Failed to read resolvers: %v\n", err)
		os.Exit(1)
	}

	// Query all resolvers concurrently
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

	// Collect results
	var results []result
	for r := range resCh {
		if verbose && r.Err == nil {
			fmt.Printf("resolver: %s / response: [%s]\n", r.Resolver, joinIPs(r.IPs))
		} else if verbose && r.Err != nil {
			fmt.Printf("resolver: %s / error: %v\n", r.Resolver, r.Err)
		}
		results = append(results, r)
	}

	// Run CDN Detection
	cdnResult := detectCDN(results)

	// Pick one working resolver for LB detection heuristics
	var selectedResolver string
	for _, r := range results {
		if r.Err == nil {
			selectedResolver = r.Resolver
			break
		}
	}

	// Run Load Balancer Detection
	lbResult := "NO LOAD BALANCER DETECTED"
	if selectedResolver != "" {
		lbResult = detectLoadBalancer(targetFQDN, selectedResolver)
	}

	// Print final classification
	fmt.Println("----- Detection Summary -----")
	fmt.Printf("CDN Status        : %s\n", cdnResult)
	fmt.Printf("Load Balancer     : %s\n", lbResult)
}
