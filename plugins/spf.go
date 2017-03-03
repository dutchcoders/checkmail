package plugins

import (
	"fmt"

	"bufio"
	"os"
	"strings"

	"github.com/fatih/color"
	dns "github.com/miekg/dns"
)

var (
	_ = Register(SPFPlugin)
)

func SPFPlugin(options ...OptionFn) Plugin {
	return &spfPlugin{}
}

type spfPlugin struct {
}

func (d *spfPlugin) Name() string {
	return "SPF"
}

func (p *spfPlugin) Check(domain string) <-chan Issue {
	issuesChan := make(chan Issue)

	go func() {
		defer close(issuesChan)

		found := false

		defer func() {
			if found {
				issuesChan <- Issue{
					Severity: SeverityOK,
					Message:  fmt.Sprintf("SPF Records configured"),
				}
			} else {
				issuesChan <- Issue{
					Severity: SeverityError,
					Message:  fmt.Sprintf("No SPF records configured."),
				}
			}
		}()

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
				// https://emailcopilot.com/blog/how-should-i-end-my-spf-record-all/

				allPolicy := "?"

				str := strings.Join(txt.Txt, "")
				if !strings.HasPrefix(str, "v=spf1") {
					continue
				}

				issuesChan <- Issue{
					Severity: SeverityInfo,
					Message:  fmt.Sprintf("%s", str),
				}

				found = true

				// check version
				scanner := bufio.NewScanner(strings.NewReader(str))

				scanner.Split(bufio.ScanWords)

				for scanner.Scan() {
					text := scanner.Text()

					text = strings.TrimSpace(text)

					if text == "all" {
						issuesChan <- Issue{
							Severity:    SeverityError,
							Message:     fmt.Sprintf("Configuration error, all defaults to +all."),
							Description: "",
						}
					}

					rule := "+"
					switch text[0] {
					case '+':
						rule = "+"
						text = text[1:]
					case '?':
						rule = "?"
						text = text[1:]
					case '~':
						rule = "~"
						text = text[1:]
					case '-':
						rule = "-"
						text = text[1:]
					}

					switch {
					case strings.HasPrefix(text, "ip4:"):
						// check for broad ip4 net
					case strings.HasPrefix(text, "ip6:"):
						// check for broad ip6 net
					case strings.HasPrefix(text, "mx"):
					case strings.HasPrefix(text, "ptr"):
						issuesChan <- Issue{
							Severity: SeverityWarning,
							Message: fmt.Sprintf("warning: %s\n", color.RedString("PTR	If the domain name (PTR record) for the client's address is in the given domain and that domain name resolves to the client's address (forward-confirmed reverse DNS), match. This mechanism is deprecated and should no longer be used.[6]")),
						}
					case strings.HasPrefix(text, "exists"):
						issuesChan <- Issue{
							Severity: SeverityWarning,
							Message:  fmt.Sprintf("warning %s\n", color.RedString("If the given domain name resolves to any address, match (no matter the address it resolves to). This is rarely used. Along with the SPF macro language it offers more complex matches like DNSBL-queries.")),
						}
					case text == "all":
						allPolicy = rule
					case text == "a":
					case strings.HasPrefix(text, "include:"):
					}
				}

				if err := scanner.Err(); err != nil {
					fmt.Fprintln(os.Stderr, "reading input:", err)
				}

				switch allPolicy {
				case "+":
					issuesChan <- Issue{
						Severity:    SeverityError,
						Message:     fmt.Sprintf("SPF rule configured all to PASS"),
						Description: "Allow all mail",
					}
				case "?":
					issuesChan <- Issue{
						Severity:    SeverityError,
						Message:     fmt.Sprintf("SPF rule configured all to NEUTRAL"),
						Description: "No policy statement",
					}
				case "~":
					issuesChan <- Issue{
						Severity:    SeverityWarning,
						Message:     fmt.Sprintf("SPF rule configured all to SOFT_FAIL"),
						Description: "Allow mail whether or not it matches the parameters in the record",
					}
				case "-":
					issuesChan <- Issue{
						Severity:    SeverityOK,
						Message:     fmt.Sprintf("SPF rule configured all to FAIL"),
						Description: "Only allow mail that matches one of the parameters (IPv4, MX, etc) in the record",
					}
				}
			} else {
				fmt.Printf("could not cast %#v\n", a)
			}
		}
	}()

	return issuesChan
}
