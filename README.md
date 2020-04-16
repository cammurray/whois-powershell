# WHOIS PowerShell Module

## Introduction

Old school whois was never really meant to be programatically parsed. This is an attempt to do something that was never really meant to happen.

## How does it work

We use the WHOIS protocol (contacting WHOIS servers on TCP 43). The raw results are attempted to be parsed with these rules in mind (saying that, with WHOIS there doesnt appear to be rules..)
* Property / Values are parsed as "Property : Value"
* Objects are determined by a carriage return on an empty line
* DateTimes are attempted to be parsed

We follow referers so we can hit the registrar with the most information.

## FAQ

### Why is it so dirty and messy? Why is it erroring?

Yes. It's dirty. This is because WHOIS as a protocol was never really meant to be machine parsed, it was meant to be human readable. We are doing lots of regex matches, one or two "attempts" to parse things and failing back to strings (like the presence of a DateTime). 

In the end what you have is a **mainly useable WHOIS module** that will most likely work but will some times not.

### But what about x API for doing WHOIS?

Yes. It's correct that there are API's out there that can do WHOIS. I haven't yet found one though that follows referers/allows me to query different TLDs/and IP addresses.