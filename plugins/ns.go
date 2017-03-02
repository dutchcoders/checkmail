package plugins

import (
	"fmt"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(NSPlugin)
)

func NSPlugin(options ...OptionFn) Plugin {
	return &nsPlugin{}
}

type nsPlugin struct {
}

func (d *nsPlugin) Name() string {
	return "NS"
}

func (p *nsPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		r, err := r.Resolve(fmt.Sprintf("%s.", domain), dns.TypeNS)
		if err != nil {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving NS records: %s", err.Error()),
			}
			return
		}

		if r.Rcode != dns.RcodeSuccess {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving NS record: %s", dns.RcodeToString[r.Rcode]),
			}
			return
		}

		for _, a := range r.Answer {
			if ns, ok := a.(*dns.NS); ok {
				// todo(nl5887): reverse dns
				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("found nameserver: %s", ns.Ns),
				}
			}
		}

	}()

	return issuesChan
}
