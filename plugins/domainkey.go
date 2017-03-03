package plugins

import (
	"fmt"

	"bufio"
	dns "github.com/miekg/dns"
	"strings"
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
					Message:  fmt.Sprintf("No DomainKey records configured, defaults to o=~. DomainKeys has been superseded by dkim."),
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

		policy := "o=~"

		for _, a := range r.Answer {
			if txt, ok := a.(*dns.TXT); ok {
				policy = strings.Join(txt.Txt, "")

				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("DomainKey %s", txt.Txt),
				}

			}
		}

		/*
			The data of this TXT-record contains the policy which is basically either "o=-" or "o=~".
			"o=-" means "all e-mails from this domain are signed", and "o=~" means "some e-mails from this domain are signed".
			Additional fields for test (t), responsible e-mail address (r), and notes (n) may also be included - for example "o=-; n=some notes".
		*/

		scanner := bufio.NewScanner(strings.NewReader(policy))

		onSemiColon := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			for i := 0; i < len(data); i++ {
				if data[i] == ';' {
					return i + 1, data[:i], nil
				}
			}
			// There is one final token to be delivered, which may be the empty string.
			// Returning bufio.ErrFinalToken here tells Scan there are no more tokens after this
			// but does not trigger an error to be returned from Scan itself.
			return 0, data, bufio.ErrFinalToken
		}

		scanner.Split(onSemiColon)

		for scanner.Scan() {
			text := scanner.Text()

			text = strings.TrimSpace(text)

			parts := strings.Split(text, "=")

			if len(parts) != 2 {
				continue
			}

			switch parts[0][0] {
			case 'o':
				if parts[1][0] == '~' {
					issuesChan <- Issue{
						Severity: SeverityInfo,
						Message:  fmt.Sprintf("Some e-mails from this domain are signed."),
					}

				} else if parts[1][0] == '-' {
					found = true

					issuesChan <- Issue{
						Severity: SeverityInfo,
						Message:  fmt.Sprintf("All e-mails from this domain are signed."),
					}
				} else {
					issuesChan <- Issue{
						Severity: SeverityWarning,
						Message:  fmt.Sprintf("Unknown modifier for o parameter: %s", parts[1]),
					}
				}
			case 't':
				if parts[1][0] == 'y' {
					issuesChan <- Issue{
						Severity: SeverityError,
						Message:  fmt.Sprintf("DomainKey in test mode, domain key has no effect."),
					}
				} else {
					issuesChan <- Issue{
						Severity: SeverityWarning,
						Message:  fmt.Sprintf("Unknown modifier for test parameter: %s", parts[1]),
					}
				}
			case 'r':
				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("DomainKey responsible e-mail address: %s", parts[1]),
				}
			case 'n':
				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("DomainKey notes: %s", parts[1]),
				}
			}
		}
	}()

	return issuesChan
}
