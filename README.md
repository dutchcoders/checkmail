# Check Email
[![Build Status - Master](https://travis-ci.org/dutchcoders/checkmail.svg?branch=master)](https://travis-ci.org/dutchcoders/checkmail)
[![Project Status](http://opensource.box.com/badges/active.svg)](http://opensource.box.com/badges)
[![Project Status](http://opensource.box.com/badges/maintenance.svg)](http://opensource.box.com/badges)
[![Average time to resolve an issue](http://isitmaintained.com/badge/resolution/dutchcoders/checkmail.svg)](http://isitmaintained.com/project/major/MySQLTuner-perl "Average time to resolve an issue")
[![Percentage of issues still open](http://isitmaintained.com/badge/open/dutchcoders/checkmail.svg)](http://isitmaintained.com/project/dutchcoders/checkmail "Percentage of issues still open")
[![GPL Licence](https://badges.frapsoft.com/os/gpl/gpl.png?v=103)](https://opensource.org/licenses/GPL-3.0/)

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

