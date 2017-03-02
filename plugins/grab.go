package plugins

import (
	"fmt"

	"github.com/zmap/zgrab/zlib"
	"os"
	"time"

	"github.com/zmap/zgrab/ztools/zlog"
	"github.com/zmap/zgrab/ztools/ztls"
	"net"

	dns "github.com/miekg/dns"
)

var (
	_ = Register(GrabPlugin)
)

func GrabPlugin(options ...OptionFn) Plugin {
	return &grabPlugin{}
}

type grabPlugin struct {
}

func (d *grabPlugin) Name() string {
	return "Banner grabbing"
}

func (p *grabPlugin) Check(domain string) <-chan Issue {
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
				config := &zlib.Config{
					Port:               25,
					Timeout:            time.Duration(5) * time.Minute, // some smtp servers have really large timeouts
					TLS:                false,
					TLSVerbose:         false,
					TLSVersion:         ztls.VersionTLS12,
					Banners:            true,
					Heartbleed:         true,
					Senders:            1,
					ConnectionsPerHost: 1,
					SMTP:               true,
					SMTPHelp:           true,
					StartTLS:           true,
					EHLO:               true,
					EHLODomain:         "amazonaws.com",
					ErrorLog:           zlog.New(os.Stderr, "banner-grab"),
					GOMAXPROCS:         1,
				}

				addrs, err := net.LookupIP(mx.Mx)

				if err != nil {
					// table.Append([]string{"Grab", "Could not resolve", color.RedString(fmt.Sprintf("%#v %s\n", mx.Mx, err))})
				} else {
					for _, addr := range addrs {
						target := &zlib.GrabTarget{
							Addr:   addr,
							Domain: "localhost",
						}

						grab := zlib.GrabBanner(config, target)

						if grab.Data.Banner != "" {
							issuesChan <- Issue{
								Severity: SeverityInfo,
								Message:  fmt.Sprintf("Banner %s(%s) %s", mx.Mx, addr.String(), grab.Data.Banner),
							}
						}

						if grab.Data.EHLO != "" {
							issuesChan <- Issue{
								Severity: SeverityDebug,
								Message:  fmt.Sprintf("EHLO %s(%s) %s", mx.Mx, addr.String(), grab.Data.EHLO),
							}
						}

						if grab.Data.SMTPHelp != nil {
							issuesChan <- Issue{
								Severity: SeverityDebug,
								Message:  fmt.Sprintf("SMTP HELP %s(%s) %s", mx.Mx, addr.String(), *grab.Data.SMTPHelp),
							}
						}

						if grab.Data.StartTLS != "" {
							issuesChan <- Issue{
								Severity: SeverityDebug,
								Message:  fmt.Sprintf("TLS12 %s(%s) %s", mx.Mx, addr.String(), grab.Data.StartTLS),
							}
						} else {
							issuesChan <- Issue{
								Severity: SeverityError,
								Message:  fmt.Sprintf("TLS12 not supported by server %s(%s)", mx.Mx, addr.String()),
							}
						}

						if grab.Data.TLSHandshake != nil {
							// table.Append([]string{"Grab", "Server certificates", color.YellowString(fmt.Sprintf("%#v (%#v) %s\n", mx.Mx, addr.String(), grab.Data.TLSHandshake.ServerCertificates.Certificate.Parsed.Subject.String()))})

							issuesChan <- Issue{
								Severity: SeverityInfo,
								Message:  fmt.Sprintf("TLS Handshake: %s(%s) %s", mx.Mx, addr.String(), grab.Data.TLSHandshake.ServerCertificates.Certificate.Parsed.Subject.String()),
							}
							for _, sc := range grab.Data.TLSHandshake.ServerCertificates.Chain {
								// table.Append([]string{"Grab", "Server certificates", color.YellowString(fmt.Sprintf("%#v (%#v) %s\n", mx.Mx, addr.String(), sc.Parsed.Subject.String()))})
								_ = sc
							}
						}

						if grab.Data.Heartbleed == nil {
						} else if grab.Data.Heartbleed.Vulnerable {
							// table.Append([]string{"Grab", "Heartbleed", color.YellowString(fmt.Sprintf("%#v (%#v) %s\n", mx.Mx, addr.String(), "Heartbleed vulnerable"))})
						}
					}

				}
				//todo(nl5887): summary? found critical issues
			}
		}
	}()

	return issuesChan
}
