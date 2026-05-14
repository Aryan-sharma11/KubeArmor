// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package networkpolicyenforcer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	"github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ============================= //
// == Network Policy Enforcer == //
// ============================= //

// NetworkRule Structure
type NetworkRule struct { // represents a single nftables rule entry
	TableFamily string // ip or ip6
	Chain       string // INPUT or OUTPUT
	RuleContent string
}

// QuotaObj Structure
type QuotaObj struct {
	Name  string
	Limit string // pre-formatted nft quota string, e.g. "500 mbytes"
}

// NetworkPolicyEnforcer Structure
type NetworkPolicyEnforcer struct {
	// logs
	Logger *fd.Feeder

	// rules
	Rules     []NetworkRule
	RulesLock *sync.RWMutex

	cancelNflog context.CancelFunc

	ticker     *time.Ticker
	tickerDone chan bool

	// Rate Limiting Cache
	// Key: string (Flow Hash), Value: time.Time (Last Seen)
	LogCache sync.Map

	// Quotas
	QuotaTimers map[string]*time.Ticker
	QuotaCancel map[string]context.CancelFunc
	PodIPs      map[string]string
	QuotasLock  *sync.Mutex
}

// NewNetworkPolicyEnforcer Function
func NewNetworkPolicyEnforcer(logger *fd.Feeder) (*NetworkPolicyEnforcer, error) {

	// Check if running as root (UID 0)
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("requires root privileges")
	}

	// Check if the nft command is available in the system PATH
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft command not found in $PATH")
	}

	ne := &NetworkPolicyEnforcer{}

	ne.Logger = logger

	ne.Rules = []NetworkRule{}
	ne.RulesLock = &sync.RWMutex{}
	ne.QuotaTimers = make(map[string]*time.Ticker)
	ne.QuotaCancel = make(map[string]context.CancelFunc)
	ne.PodIPs = make(map[string]string)
	ne.QuotasLock = &sync.Mutex{}

	ne.ticker = time.NewTicker(1 * time.Minute)
	ne.tickerDone = make(chan bool, 1)

	// Start Cache Cleanup Routine (runs every 1 minute)
	go func() {
		for {
			select {
			case <-ne.tickerDone:
				return
			case t := <-ne.ticker.C:
				ne.LogCache.Range(func(key, value interface{}) bool {
					lastSeen := value.(time.Time)
					// If log is older than 1 minute, delete it from cache
					if t.Sub(lastSeen) > 1*time.Minute {
						ne.LogCache.Delete(key)
					}
					return true
				})
			}
		}
	}()

	// monitor logged packets
	go ne.monitorLoggedPackets()

	ne.UpdateNetworkSecurityPolicies([]tp.NetworkSecurityPolicy{}, []tp.EndPoint{}, map[string]tp.Container{})

	return ne, nil
}

func getProtocolName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	default:
		// Fallback for less common protocols
		return fmt.Sprintf("Proto-%d", p)
	}
}

// monitorLoggedPackets Function
func (ne *NetworkPolicyEnforcer) monitorLoggedPackets() {

	// Configure nflog
	config := nflog.Config{
		Group:    0,
		Copymode: nflog.CopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("could not open nflog socket: %v", err)
		}
		return
	}

	// We do not defer nf.Close() here because we want it to run in the background.
	// It will be closed when DestroyNetworkPolicyEnforcer is called.

	// Increase socket read buffer size to avoid dropped logs
	if err := nf.Con.SetReadBuffer(2 * 1024 * 1024); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("failed to set read buffer: %v", err)
		}
	}

	// Avoid receiving ENOBUFS errors
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("failed to set netlink option: %v", err)
		}
	}

	// Setup context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	ne.cancelNflog = cancel

	// Fast decoders for gopacket
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var sctp layers.SCTP
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6

	parser4 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp, &sctp, &icmp4)
	parser6 := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp, &sctp, &icmp6)

	// Ignore errors from missing layers (e.g. payload without TCP)
	parser4.IgnoreUnsupported = true
	parser6.IgnoreUnsupported = true

	// hook that is called for every received packet
	hook := func(attrs nflog.Attribute) int {
		var payload []byte
		prefix := ""

		if attrs.Payload != nil {
			payload = *attrs.Payload
		}
		if attrs.Prefix != nil {
			prefix = *attrs.Prefix
		}

		if len(payload) < 20 {
			return 0 // Too short to be a valid IP packet
		}

		var srcIP, dstIP string
		var srcPort, dstPort uint16
		var protocol uint8

		decoded := []gopacket.LayerType{}

		// Check IP version
		version := payload[0] >> 4
		if version == 4 {
			_ = parser4.DecodeLayers(payload, &decoded)
		} else if version == 6 {
			_ = parser6.DecodeLayers(payload, &decoded)
		}

		// Extract parsed data
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
				protocol = uint8(ip4.Protocol)
			case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP.String()
				dstIP = ip6.DstIP.String()
				protocol = uint8(ip6.NextHeader)
			case layers.LayerTypeTCP:
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
			case layers.LayerTypeUDP:
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			case layers.LayerTypeSCTP:
				srcPort = uint16(sctp.SrcPort)
				dstPort = uint16(sctp.DstPort)
			}
		}

		// Rate Limiting (10 Seconds)
		flowKey := fmt.Sprintf("%s:%d->%s:%d/%d-%s", srcIP, srcPort, dstIP, dstPort, protocol, prefix)
		if lastSeen, loaded := ne.LogCache.Load(flowKey); loaded {
			if time.Since(lastSeen.(time.Time)) < 10*time.Second {
				return 0 // SKIP LOGGING
			}
		}

		ne.LogCache.Store(flowKey, time.Now())

		// Generate KubeArmor Log
		log := tp.Log{}
		timestamp, updatedTime := kl.GetDateTimeNow()

		log.Timestamp = timestamp
		log.UpdatedTime = updatedTime
		log.Operation = "NetworkFirewall"
		log.Resource = prefix
		log.Data = fmt.Sprintf("SourceIP=%s SourcePort=%d DestinationIP=%s DestinationPort=%d Protocol=%s", srcIP, srcPort, dstIP, dstPort, getProtocolName(protocol))

		parts := strings.Split(prefix, " ")
		action := "Audit" // default fallback
		if len(parts) > 2 {
			action = parts[2]
		} else if strings.Contains(prefix, "Block") {
			action = "Block"
		}

		log.Action = action
		if action != "Block" {
			log.Result = "Passed"
		} else {
			log.Result = "Permission denied"
		}

		log.Enforcer = "NetworkPolicyEnforcer"

		ne.Logger.PushLog(log)

		return 0
	}

	errFunc := func(e error) int {

		// If context is cancelled (shutdown), ignore errors and return
		if ctx.Err() != nil {
			return 0
		}

		if ne.Logger != nil {
			ne.Logger.Errf("NFLOG hook error: %v", e)
		}
		return 0
	}

	// Register and block
	if err := nf.RegisterWithErrorFunc(ctx, hook, errFunc); err != nil {
		if ne.Logger != nil {
			ne.Logger.Errf("failed to register nflog hook: %v", err)
		}
		return
	}

	<-ctx.Done()
	if err := nf.Close(); err != nil {
		ne.Logger.Errf("Failed to close nflog: %v", err)
	}
}

// UpdateNetworkSecurityPolicies Function
func (ne *NetworkPolicyEnforcer) UpdateNetworkSecurityPolicies(secPolicies []tp.NetworkSecurityPolicy, endpoints []tp.EndPoint, containers map[string]tp.Container) {

	ne.RulesLock.Lock()
	defer ne.RulesLock.Unlock()

	// Clean up existing timers
	ne.QuotasLock.Lock()
	for _, cancel := range ne.QuotaCancel {
		cancel()
	}
	ne.QuotaTimers = make(map[string]*time.Ticker)
	ne.QuotaCancel = make(map[string]context.CancelFunc)
	ne.QuotasLock.Unlock()

	var newRules []NetworkRule
	var allQuotas []QuotaObj
	hasAllowPolicy := false

	// generate Rules
	for _, policy := range secPolicies {

		if strings.EqualFold(policy.Spec.Action, "Allow") {
			hasAllowPolicy = true
		}

		policyName, _ := policy.Metadata["policyName"]

		var podIPs []string
		isPodPolicy := len(policy.Spec.Selector.Identities) > 0
		if isPodPolicy {
			// Find matching endpoints and collect their pod IPs
			for _, ep := range endpoints {
				matched := kl.MatchIdentities(policy.Spec.Selector.Identities, ep.Identities)
				fmt.Printf("  Endpoint %s: matched=%v, ep.PodIP=%q\n", ep.EndPointName, matched, ep.PodIP)
				if matched {
					if ep.PodIP != "" {
						podIPs = append(podIPs, ep.PodIP)
					}
				}
			}
		}
		fmt.Println("Matched Pod IPs for policy", policyName, ":", podIPs)

		// Ingress
		for idx, ingress := range policy.Spec.Ingress {
			action := policy.Spec.Action
			if action == "" {
				action = "Block" // default action, if not specified in policy
			}

			if ingress.Action != "" {
				action = ingress.Action
			}
			rules := generateRules("Ingress", ingress.From, ingress.Ports, ingress.Interface, action, policyName, ingress.Limit, ingress.Duration, idx, &allQuotas, podIPs, isPodPolicy)
			newRules = append(newRules, rules...)

			if ingress.Limit != "" && ingress.Duration != "" {
				parsedLimit, err := parseLimitToNFT(ingress.Limit)
				if err != nil {
					ne.Logger.Errf("Policy %s ingress[%d] has invalid limit %q: %v", policyName, idx, ingress.Limit, err)
				} else {
					parsedDuration, err := parseDurationToSeconds(ingress.Duration)
					if err != nil {
						ne.Logger.Errf("Policy %s ingress[%d] has invalid duration %q: %v", policyName, idx, ingress.Duration, err)
					} else if parsedDuration > 0 {
						_ = parsedLimit // quota already registered inside generateRules
						quotaName := fmt.Sprintf("quota_%s_Ingress_%d", policyName, idx)
						quotaName = strings.ReplaceAll(quotaName, "-", "_")
						quotaName = strings.ReplaceAll(quotaName, " ", "_")
						ne.setupQuotaTimer(quotaName, parsedDuration)
					}
				}
			}
		}
		// Egress
		for idx, egress := range policy.Spec.Egress {
			action := policy.Spec.Action
			if action == "" {
				action = "Block" // default action, if not specified in policy
			}

			if egress.Action != "" {
				action = egress.Action
			}
			rules := generateRules("Egress", egress.To, egress.Ports, egress.Interface, action, policyName, egress.Limit, egress.Duration, idx, &allQuotas, podIPs, isPodPolicy)
			newRules = append(newRules, rules...)

			if egress.Limit != "" && egress.Duration != "" {
				parsedLimit, err := parseLimitToNFT(egress.Limit)
				if err != nil {
					ne.Logger.Errf("Policy %s egress[%d] has invalid limit %q: %v", policyName, idx, egress.Limit, err)
				} else {
					parsedDuration, err := parseDurationToSeconds(egress.Duration)
					if err != nil {
						ne.Logger.Errf("Policy %s egress[%d] has invalid duration %q: %v", policyName, idx, egress.Duration, err)
					} else if parsedDuration > 0 {
						_ = parsedLimit // quota already registered inside generateRules
						quotaName := fmt.Sprintf("quota_%s_Egress_%d", policyName, idx)
						quotaName = strings.ReplaceAll(quotaName, "-", "_")
						quotaName = strings.ReplaceAll(quotaName, " ", "_")
						ne.setupQuotaTimer(quotaName, parsedDuration)
					}
				}
			}
		}
	}

	// host log
	defaultAction := "accept"
	actionKeyword := "Allow"
	policyName := "Host" // for host logs

	// add Default Posture Rule (Catch-All) if an Allow policy exists, else rule for Host Logs
	if hasAllowPolicy {
		defaultAction = "drop"
		actionKeyword = "Block"
		policyName = "Default" // for default posture alerts

		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			defaultAction = "accept"
			actionKeyword = "Audit"
		}
	}

	// log prefix format: "PolicyName Chain Action" (e.g., "Default INPUT Block")

	// INPUT Rule
	inputPrefix := fmt.Sprintf("%s INPUT %s", policyName, actionKeyword)
	inputRule := fmt.Sprintf("log prefix %q group 0 %s", inputPrefix, defaultAction)

	// OUTPUT Rule
	outputPrefix := fmt.Sprintf("%s OUTPUT %s", policyName, actionKeyword)
	outputRule := fmt.Sprintf("log prefix %q group 0 %s", outputPrefix, defaultAction)

	// Append rules
	newRules = append(newRules,
		NetworkRule{TableFamily: "ip", Chain: "INPUT", RuleContent: inputRule},
		NetworkRule{TableFamily: "ip", Chain: "OUTPUT", RuleContent: outputRule},
		NetworkRule{TableFamily: "ip6", Chain: "INPUT", RuleContent: inputRule},
		NetworkRule{TableFamily: "ip6", Chain: "OUTPUT", RuleContent: outputRule},
	)

	ne.Rules = newRules

	if err := ne.applyNFTables(hasAllowPolicy, allQuotas); err != nil {
		ne.Logger.Errf("Failed to apply network policies: %v", err)
	}
}

func parseLimitToNFT(limit string) (string, error) {
	if limit == "" {
		return "", fmt.Errorf("empty limit")
	}
	limit = strings.TrimSpace(limit)

	// Split numeric prefix from unit suffix
	i := 0
	for i < len(limit) && (limit[i] >= '0' && limit[i] <= '9') {
		i++
	}
	if i == 0 {
		return "", fmt.Errorf("invalid limit %q: no numeric prefix", limit)
	}

	value, err := strconv.ParseUint(limit[:i], 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid limit value %q: %v", limit[:i], err)
	}

	unit := strings.ToUpper(strings.TrimSpace(limit[i:]))

	var bytes uint64
	switch unit {
	case "KB", "K":
		bytes = value * 1024
	case "MB", "M":
		bytes = value * 1024 * 1024
	case "GB", "G", "":
		// default to GB if no unit given
		bytes = value * 1024 * 1024 * 1024
	default:
		return "", fmt.Errorf("invalid limit unit %q: expected KB, MB, or GB", unit)
	}

	return fmt.Sprintf("%d bytes", bytes), nil
}

func parseDurationToSeconds(d string) (uint32, error) {
	if d == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(d)
	if err != nil {
		return 0, err
	}
	return uint32(parsed.Seconds()), nil
}

func generateRules(direction string, peers []tp.NetworkPeer, ports []tp.PortType, ifaces []string, action, policyName string, limit string, duration string, ruleIdx int, quotas *[]QuotaObj, podIPs []string, isPodPolicy bool) []NetworkRule {
	var rules []NetworkRule

	if isPodPolicy && len(podIPs) == 0 {
		return rules // Do not generate any rules if it's a pod policy but no pods are scheduled on this node
	}

	quotaName := ""
	if limit != "" && duration != "" {
		parsedDuration, _ := parseDurationToSeconds(duration)
		if parsedDuration > 0 {
			parsed, err := parseLimitToNFT(limit)
			if err == nil {
				quotaName = fmt.Sprintf("quota_%s_%s_%d", policyName, direction, ruleIdx)
				quotaName = strings.ReplaceAll(quotaName, "-", "_")
				quotaName = strings.ReplaceAll(quotaName, " ", "_")
				*quotas = append(*quotas, QuotaObj{Name: quotaName, Limit: parsed})
			}
		}
	}

	// Allow -> accept (no log)
	// Block -> log + drop
	// Audit -> log + accept

	nftAction := "drop"
	shouldLog := true

	act := strings.ToLower(action)
	switch act {
	case "allow":
		nftAction = "accept"
		shouldLog = false
	case "audit":
		nftAction = "accept"
		shouldLog = true
	default:
		// Block
		nftAction = "drop"
		shouldLog = true
	}

	logPrefix := policyName + " " + direction + " " + action

	// Collect CIDRs
	var ipv4CIDRs []string
	var ipv6CIDRs []string
	for _, peer := range peers {
		if peer.IPBlock == nil || peer.IPBlock.CIDR == "" {
			continue
		}

		if strings.Contains(peer.IPBlock.CIDR, ":") {
			ipv6CIDRs = append(ipv6CIDRs, peer.IPBlock.CIDR)
		} else {
			ipv4CIDRs = append(ipv4CIDRs, peer.IPBlock.CIDR)
		}
	}

	var podIPv4s []string
	var podIPv6s []string
	for _, ip := range podIPs {
		if strings.Contains(ip, ":") {
			podIPv6s = append(podIPv6s, ip)
		} else {
			podIPv4s = append(podIPv4s, ip)
		}
	}

	// Collect interfaces
	var ifaceSet []string
	for _, iface := range ifaces {
		if iface != "" {
			ifaceSet = append(ifaceSet, fmt.Sprintf("%q", iface))
		}
	}

	// Collect ports
	protoPorts := map[string][]string{} // protocol -> ports
	for _, port := range ports {

		if port.Port == "" {
			continue
		}

		proto := "tcp"
		if port.Protocol != "" {
			proto = strings.ToLower(port.Protocol)
		}

		startPort := resolvePort(port.Port)

		finalPort := startPort
		if port.EndPort != nil {
			finalPort = fmt.Sprintf("%s-%d", startPort, *port.EndPort)
		}

		protoPorts[proto] = append(protoPorts[proto], finalPort)
	}

	buildRule := func(tableFamily, addrFamily string, cidrs []string, pods []string) {
		var chains []string
		if isPodPolicy {
			// Pod-level rules always go to inet FORWARD chain
			chains = []string{"FORWARD"}
		} else {
			// Host-level rules: INPUT or OUTPUT in ip/ip6 tables
			if direction == "Ingress" {
				chains = []string{"INPUT"}
			} else {
				chains = []string{"OUTPUT"}
			}
		}

		// If no ports specified, build a single rule
		if len(protoPorts) == 0 {
			var parts []string

			// Interface
			if len(ifaceSet) > 0 {
				op := "iifname"
				if direction == "Egress" {
					op = "oifname"
				}

				if len(ifaceSet) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s", op, ifaceSet[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s { %s }", op, strings.Join(ifaceSet, ", ")))
				}
			}

			// CIDR (Peers) — use addrFamily prefix so it works in both ip and inet tables
			if len(cidrs) > 0 {
				dir := "saddr"
				if direction == "Egress" {
					dir = "daddr"
				}

				if len(cidrs) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, cidrs[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(cidrs, ", ")))
				}
			}

			// Pods — use addrFamily prefix
			if len(pods) > 0 {
				dir := "daddr"
				if direction == "Egress" {
					dir = "saddr"
				}

				if len(pods) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, pods[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(pods, ", ")))
				}
			}

			if quotaName != "" {
				overParts := append([]string(nil), parts...)
				overParts = append(overParts, fmt.Sprintf("quota name %q", quotaName))
				if shouldLog {
					overParts = append(overParts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				overParts = append(overParts, nftAction)

				underParts := append([]string(nil), parts...)
				underParts = append(underParts, "accept")

				for _, ch := range chains {
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(overParts, " "),
					})
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(underParts, " "),
					})
				}
			} else {
				if shouldLog {
					parts = append(parts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				parts = append(parts, nftAction)
				for _, ch := range chains {
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(parts, " "),
					})
				}
			}

			return
		}

		// Build rule per protocol
		for proto, ports := range protoPorts {
			var parts []string

			// Interface
			if len(ifaceSet) > 0 {
				op := "iifname"
				if direction == "Egress" {
					op = "oifname"
				}

				if len(ifaceSet) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s", op, ifaceSet[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s { %s }", op, strings.Join(ifaceSet, ", ")))
				}
			}

			// CIDR (Peers) — use addrFamily prefix so it works in both ip and inet tables
			if len(cidrs) > 0 {
				dir := "saddr"
				if direction == "Egress" {
					dir = "daddr"
				}

				if len(cidrs) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, cidrs[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(cidrs, ", ")))
				}
			}

			// Pods — use addrFamily prefix
			if len(pods) > 0 {
				dir := "daddr"
				if direction == "Egress" {
					dir = "saddr"
				}

				if len(pods) == 1 {
					parts = append(parts, fmt.Sprintf("%s %s %s", addrFamily, dir, pods[0]))
				} else {
					parts = append(parts, fmt.Sprintf("%s %s { %s }", addrFamily, dir, strings.Join(pods, ", ")))
				}
			}

			// Ports
			if len(ports) == 1 {
				parts = append(parts, fmt.Sprintf("%s dport %s", proto, ports[0]))
			} else {
				parts = append(parts, fmt.Sprintf("%s dport { %s }", proto, strings.Join(ports, ", ")))
			}

			if quotaName != "" {
				overParts := append([]string(nil), parts...)
				overParts = append(overParts, fmt.Sprintf("quota name %q", quotaName))
				if shouldLog {
					overParts = append(overParts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				overParts = append(overParts, nftAction)

				underParts := append([]string(nil), parts...)
				underParts = append(underParts, "accept")

				for _, ch := range chains {
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(overParts, " "),
					})
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(underParts, " "),
					})
				}
			} else {
				if shouldLog {
					parts = append(parts, fmt.Sprintf("log prefix %q group 0", logPrefix))
				}
				parts = append(parts, nftAction)
				for _, ch := range chains {
					rules = append(rules, NetworkRule{
						TableFamily: tableFamily,
						Chain:       ch,
						RuleContent: strings.Join(parts, " "),
					})
				}
			}
		}
	}

	if !isPodPolicy || len(podIPv4s) > 0 {
		if quotaName != "" || isPodPolicy {
			// Pod rules (quota or not) go to inet table
			buildRule("inet", "ip", ipv4CIDRs, podIPv4s)
		} else {
			// Host-only rules stay in ip table
			buildRule("ip", "ip", ipv4CIDRs, podIPv4s)
		}
	}

	if !isPodPolicy || len(podIPv6s) > 0 {
		if quotaName != "" || isPodPolicy {
			// Pod rules (quota or not) go to inet table
			buildRule("inet", "ip6", ipv6CIDRs, podIPv6s)
		} else {
			// Host-only rules stay in ip6 table
			buildRule("ip6", "ip6", ipv6CIDRs, podIPv6s)
		}
	}

	return rules
}

func (ne *NetworkPolicyEnforcer) applyNFTables(hasAllowPolicy bool, quotas []QuotaObj) error {
	chainPolicy := "accept"
	if hasAllowPolicy {
		if cfg.GlobalCfg.HostDefaultNetworkPosture == "audit" {
			chainPolicy = "accept"
		} else {
			chainPolicy = "drop"
		}
	}

	const nftTemplate = `
# 1. Define ip and ip6 tables for host-level rules (INPUT/OUTPUT only)
add table ip kubearmor
add table ip6 kubearmor

# 2. Define inet table for pod-level rules and quota tracking
add table inet kubearmor
{{- range .Quotas }}
add quota inet kubearmor {{.Name}} { over {{.Limit}} }
{{- end }}

# 3. Define chains
add chain ip kubearmor INPUT { type filter hook input priority 0; policy {{.ChainPolicy}}; }
add chain ip kubearmor OUTPUT { type filter hook output priority 0; policy {{.ChainPolicy}}; }

add chain ip6 kubearmor INPUT { type filter hook input priority 0; policy {{.ChainPolicy}}; }
add chain ip6 kubearmor OUTPUT { type filter hook output priority 0; policy {{.ChainPolicy}}; }

add chain inet kubearmor FORWARD { type filter hook forward priority 1; policy accept; }
add chain inet kubearmor INPUT { type filter hook input priority 1; policy accept; }
add chain inet kubearmor OUTPUT { type filter hook output priority 1; policy accept; }

# 4. Flush old rules
flush chain ip kubearmor INPUT
flush chain ip kubearmor OUTPUT

flush chain ip6 kubearmor INPUT
flush chain ip6 kubearmor OUTPUT

flush chain inet kubearmor FORWARD
flush chain inet kubearmor INPUT
flush chain inet kubearmor OUTPUT

# 5. Add new rules
table ip kubearmor {
	chain INPUT {
		iifname "lo" accept
        ct state { established, related } accept

		{{- range .IPv4Input }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		oifname "lo" accept
        ct state { established, related } accept

		{{- range .IPv4Output }}
		{{ . }}
		{{- end }}
	}
}

table ip6 kubearmor {
	chain INPUT {
		iifname "lo" accept
        ct state { established, related } accept

		{{- range .IPv6Input }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		oifname "lo" accept
        ct state { established, related } accept

		{{- range .IPv6Output }}
		{{ . }}
		{{- end }}
	}
}

table inet kubearmor {
	chain FORWARD {
		{{- range .InetForward }}
		{{ . }}
		{{- end }}
	}
	chain INPUT {
		{{- range .InetInput }}
		{{ . }}
		{{- end }}
	}
	chain OUTPUT {
		{{- range .InetOutput }}
		{{ . }}
		{{- end }}
	}
}
`
	data := struct {
		ChainPolicy string
		Quotas      []QuotaObj
		IPv4Input   []string
		IPv4Output  []string
		IPv6Input   []string
		IPv6Output  []string
		InetForward []string
		InetInput   []string
		InetOutput  []string
	}{
		ChainPolicy: chainPolicy,
		Quotas:      quotas,
	}

	// Sort rules into categories
	for _, rule := range ne.Rules {
		switch rule.TableFamily {
		case "ip":
			if rule.Chain == "INPUT" {
				data.IPv4Input = append(data.IPv4Input, rule.RuleContent)
			} else {
				data.IPv4Output = append(data.IPv4Output, rule.RuleContent)
			}
		case "ip6":
			if rule.Chain == "INPUT" {
				data.IPv6Input = append(data.IPv6Input, rule.RuleContent)
			} else {
				data.IPv6Output = append(data.IPv6Output, rule.RuleContent)
			}
		case "inet":
			if rule.Chain == "FORWARD" {
				data.InetForward = append(data.InetForward, rule.RuleContent)
			} else if rule.Chain == "INPUT" {
				data.InetInput = append(data.InetInput, rule.RuleContent)
			} else {
				data.InetOutput = append(data.InetOutput, rule.RuleContent)
			}
		}
	}

	t := template.Must(template.New("nft").Parse(nftTemplate))

	tmpFile, err := os.CreateTemp("", "ka-nft-rules-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if err := t.Execute(tmpFile, data); err != nil {
		if closeError := tmpFile.Close(); closeError != nil {
			return closeError
		}
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Apply using nft -f
	cmd := exec.Command("nft", "-f", tmpFile.Name()) // #nosec G204
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft apply error: %v\nnft apply output: %s", err, string(output))
	}

	return nil
}

func (ne *NetworkPolicyEnforcer) setupQuotaTimer(quotaName string, durationSeconds uint32) {
	if durationSeconds == 0 {
		return
	}

	ne.QuotasLock.Lock()
	defer ne.QuotasLock.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	ne.QuotaCancel[quotaName] = cancel

	ticker := time.NewTicker(time.Duration(durationSeconds) * time.Second)
	ne.QuotaTimers[quotaName] = ticker

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Reset the single inet quota — covers both IPv4 and IPv6 traffic
				exec.Command("nft", "reset", "quota", "inet", "kubearmor", quotaName).Run() // #nosec G204
			}
		}
	}()
}

func resolvePort(port string) string {
	if _, err := strconv.Atoi(port); err == nil {
		return port
	}
	services := map[string]string{"ssh": "22", "http": "80", "https": "443", "dns": "53"}
	if val, ok := services[strings.ToLower(port)]; ok {
		return val
	}
	return port
}

// DestroyNetworkPolicyEnforcer Function
func (ne *NetworkPolicyEnforcer) DestroyNetworkPolicyEnforcer() error {
	// skip if Network Policy Enforcer is not active
	if ne == nil {
		return nil
	}

	// ticker and cache cleanup goroutine
	if ne.ticker != nil {
		ne.ticker.Stop()
	}
	select {
	case ne.tickerDone <- true:
	default:
	}

	ne.QuotasLock.Lock()
	for _, t := range ne.QuotaTimers {
		t.Stop()
	}
	for _, cancel := range ne.QuotaCancel {
		cancel()
	}
	ne.QuotasLock.Unlock()

	// nflog listener
	if ne.cancelNflog != nil {
		ne.cancelNflog()
	}

	// cleanup nftables tables
	for _, family := range []string{"ip", "ip6", "inet"} {
		cmd := exec.Command("nft", "delete", "table", family, "kubearmor") // #nosec G204
		_ = cmd.Run()                                                      // Ignore error if table doesn't exist
	}

	ne = nil
	return nil
}
