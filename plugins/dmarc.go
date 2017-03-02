package plugins

import (
	"fmt"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(DMARCPlugin)
)

func DMARCPlugin(options ...OptionFn) Plugin {
	return &dmarcPlugin{}
}

type dmarcPlugin struct {
}

func (d *dmarcPlugin) Name() string {
	return "DMARC"
}

func (p *dmarcPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		found := false

		defer func() {
			if found {
				issuesChan <- Issue{
					Severity: SeverityOK,
					Message:  fmt.Sprintf("DMARC Records configured"),
				}
			} else {
				issuesChan <- Issue{
					Severity: SeverityError,
					Message:  fmt.Sprintf("No DMARC records configured."),
				}
			}
		}()

		r, err := r.Resolve(fmt.Sprintf("_dmarc.%s.", domain), dns.TypeTXT)
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
				found = true

				// todo(nl5887): reverse dns
				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("DMARC %s", txt.Txt),
				}
			}
		}

	}()

	return issuesChan
}
