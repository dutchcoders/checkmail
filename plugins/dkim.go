package plugins

import (

	// "github.com/dutchcoders/check-email-settings/client"

	"fmt"
	"github.com/miekg/dns"
	"strings"
)

var (
	_ = Register(DKIMPlugin)
)

func DKIMPlugin(options ...OptionFn) Plugin {
	return &dkimPlugin{}
}

type dkimPlugin struct {
}

func (d *dkimPlugin) Name() string {
	return "DKIM"
}

func (d *dkimPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		found := false

		defer func() {
			if found {
				issuesChan <- Issue{
					Severity: SeverityOK,
					Message:  fmt.Sprintf("Found default DKIM Records configured"),
				}
			} else {
				issuesChan <- Issue{
					Severity: SeverityWarning,
					Message:  fmt.Sprintf("No default DKIM records configured."),
				}
			}
		}()

		for _, selector := range []string{"dkim", "default"} {
			r, err := r.Resolve(fmt.Sprintf("%s._domainkey.%s.", selector, domain), dns.TypeTXT)
			if err != nil {
				issuesChan <- Issue{
					Severity: SeverityError,
					Message:  fmt.Sprintf("Error retrieving record for selector '%s': %s", selector, err.Error()),
				}

				continue
			}

			if r.Rcode != dns.RcodeSuccess {
				issuesChan <- Issue{
					Severity: SeverityDebug,
					Message:  fmt.Sprintf("Error retrieving record for selector '%s': %s", selector, dns.RcodeToString[r.Rcode]),
				}

				continue
			}

			for _, a := range r.Answer {
				if txt, ok := a.(*dns.TXT); ok {
					str := strings.Join(txt.Txt, "")

					issuesChan <- Issue{
						Severity: SeverityInfo,
						Message:  fmt.Sprintf("DKIM record for selector '%s': %s", selector, str),
					}

					found = true
				}
			}
		}
	}()

	return issuesChan
}
