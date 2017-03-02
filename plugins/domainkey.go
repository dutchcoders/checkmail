package plugins

import (
	"fmt"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(DomainKeyPlugin)
)

func DomainKeyPlugin(options ...OptionFn) Plugin {
	return &domainKeyPlugin{}
}

type domainKeyPlugin struct {
}

func (d *domainKeyPlugin) Name() string {
	return "DomainKey"
}

func (p *domainKeyPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		found := false

		defer func() {
			if found {
				issuesChan <- Issue{
					Severity: SeverityOK,
					Message:  fmt.Sprintf("DomainKey Records configured"),
				}
			} else {
				issuesChan <- Issue{
					Severity: SeverityWarning,
					Message:  fmt.Sprintf("No DomainKey records configured."),
				}
			}
		}()

		r, err := r.Resolve(fmt.Sprintf("_domainkey.%s.", domain), dns.TypeTXT)
		if err != nil {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving TXT records: %s", err.Error()),
			}
			return
		}

		if r.Rcode != dns.RcodeSuccess {
			issuesChan <- Issue{
				Severity: SeverityDebug,
				Message:  fmt.Sprintf("Error retrieving TXT record: %s", dns.RcodeToString[r.Rcode]),
			}
			return
		}

		for _, a := range r.Answer {
			if txt, ok := a.(*dns.TXT); ok {
				// todo(nl5887): reverse dns
				found = true

				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("DomainKey %s", txt.Txt),
				}
			}
		}

	}()

	return issuesChan
}
