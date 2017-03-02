package plugins

import (
	"fmt"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(TXTPlugin)
)

func TXTPlugin(options ...OptionFn) Plugin {
	return &txtPlugin{}
}

type txtPlugin struct {
}

func (d *txtPlugin) Name() string {
	return "TXT"
}

func (p *txtPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		r, err := r.Resolve(fmt.Sprintf("%s.", domain), dns.TypeTXT)
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
				for _, txt1 := range txt.Txt {
					issuesChan <- Issue{
						Severity: SeverityInfo,
						Message:  fmt.Sprintf("%s", txt1),
					}
				}
			} else {
				fmt.Printf("could not cast %#v\n", a)
			}
		}
	}()

	return issuesChan
}
