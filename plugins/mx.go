package plugins

import (
	"fmt"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(MXPlugin)
)

func MXPlugin(options ...OptionFn) Plugin {
	return &mxPlugin{}
}

type mxPlugin struct {
}

func (d *mxPlugin) Name() string {
	return "MX"
}

func (p *mxPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		r, err := r.Resolve(fmt.Sprintf("%s.", domain), dns.TypeMX)
		if err != nil {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving MX records: %s", err.Error()),
			}
			return
		}

		if r.Rcode != dns.RcodeSuccess {
			issuesChan <- Issue{
				Severity: SeverityError,
				Message:  fmt.Sprintf("Error retrieving MX record: %s", dns.RcodeToString[r.Rcode]),
			}
			return
		}

		for _, a := range r.Answer {
			if mx, ok := a.(*dns.MX); ok {
				// todo(nl5887): reverse dns
				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("mail server %s with preference %d", mx.Mx, mx.Preference),
				}
			}
		}

	}()

	return issuesChan
}
