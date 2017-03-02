# Check Email

Check domain and email security configuration. 

## Implemented checks:

* has DNSSec been configured?
* has DMARC been configured?
* has default DKIM selectors been configured (this is just informational, we cannot check for real dkim selectors)?
* does the smtp server support tls12
* has SPF been configured and does it fail all

## Known issues:
* tls12 not supported will be returned by large timeouts and if ipv6 is not supported
* dkim checks for a few default selectors (default, dkim) but not having those doesn't mean dkim is not configured. 

