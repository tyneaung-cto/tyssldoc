package checks

import (
	"context"
	"net"
)

func RunDNSChecks(ctx context.Context, target Target) DNSResult {
	resolver := net.Resolver{}
	res := DNSResult{}

	if ips, err := resolver.LookupIP(ctx, "ip4", target.Host); err == nil {
		for _, ip := range ips {
			res.ARecords = append(res.ARecords, ip.String())
		}
	} else {
		res.Warnings = append(res.Warnings, "A record lookup failed: "+err.Error())
	}

	if ips, err := resolver.LookupIP(ctx, "ip6", target.Host); err == nil {
		for _, ip := range ips {
			res.AAAARecords = append(res.AAAARecords, ip.String())
		}
	} else {
		res.Warnings = append(res.Warnings, "AAAA record lookup failed: "+err.Error())
	}

	if cname, err := resolver.LookupCNAME(ctx, target.Host); err == nil {
		res.CNAME = cname
	} else {
		res.InfoOrWarnCNAME(err)
	}

	if len(res.ARecords) == 0 && len(res.AAAARecords) == 0 {
		res.Failures = append(res.Failures, "no A or AAAA records resolved")
	}

	return res
}

func (d *DNSResult) InfoOrWarnCNAME(err error) {
	d.Warnings = append(d.Warnings, "CNAME lookup failed: "+err.Error())
}
