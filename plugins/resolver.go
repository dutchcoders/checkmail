package plugins

import (
	dns "github.com/miekg/dns"
	"math/rand"
	"net"
)

var (
	r = Resolver()
)

func Question(z string, t uint16) question {
	return question{
		z:          z,
		t:          t,
		resultChan: make(chan *dns.Msg),
		errorChan:  make(chan error),
	}
}

type question struct {
	z string
	t uint16

	resultChan chan *dns.Msg
	errorChan  chan error
}

func Resolver() *resolver {
	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")

	c := new(dns.Client)
	c.Net = "tcp"

	queue := make(chan question)

	go func() {
		for {
			question := <-queue

			func() {
				retry := 0
				for {
					m := new(dns.Msg)
					m.SetQuestion(question.z, question.t)

					i := rand.Intn(len(conf.Servers))

					r, _, err := c.Exchange(m, net.JoinHostPort(conf.Servers[i], conf.Port))
					if err != nil {
						if retry > 5 {
							question.errorChan <- err
							return
						}

						retry++
						continue
					}

					/*
						if r.Rcode != dns.RcodeSuccess {
							issuesChan <- Issue{
								Severity: SeverityError,
								Message:  fmt.Sprintf("Error retrieving DNSKey record: %s", dns.RcodeToString[r.Rcode]),
							}
							return
						}
					*/

					question.resultChan <- r
					return
				}
			}()
		}
	}()

	return &resolver{
		queue: queue,
	}
}

type resolver struct {
	queue chan question
}

func (r *resolver) Resolve(z string, t uint16) (*dns.Msg, error) {
	question := Question(z, t)

	r.queue <- question

	select {
	case result := <-question.resultChan:
		return result, nil
	case err := <-question.errorChan:
		return nil, err
	}
}
