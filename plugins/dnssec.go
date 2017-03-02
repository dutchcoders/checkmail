package plugins

import (
	"fmt"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(DNSSecPlugin)
)

func DNSSecPlugin(options ...OptionFn) Plugin {
	return &dnssecPlugin{}
}

type dnssecPlugin struct {
}

func (d *dnssecPlugin) Name() string {
	return "DNSSec"
}

func (p *dnssecPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		found := false

		defer func() {
			if found {
				issuesChan <- Issue{
					Severity: SeverityOK,
					Message:  fmt.Sprintf("DNS Sec(urity) implemented"),
				}
			} else {
				issuesChan <- Issue{
					Severity: SeverityError,
					Message:  fmt.Sprintf("DNS Sec(urity) not implemented."),
				}
			}
		}()

		result, err := r.Resolve(fmt.Sprintf("%s.", domain), dns.TypeDNSKEY)
		if err != nil {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving DNSKey records: %s", err.Error()),
			}
			return
		}

		if result.Rcode != dns.RcodeSuccess {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving DNSKey record: %s", dns.RcodeToString[result.Rcode]),
			}
			return
		}

		for _, a := range result.Answer {
			if key, ok := a.(*dns.DNSKEY); ok {
				found = true

				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("public key: %s", key.PublicKey),
				}
			}
		}
	}()

	return issuesChan
}
