# ripe-atlas-shrugd
Fake DNS resolver check using RIPE Atlas

## Quickstart

You'll need the RIPE Atlas library:

```
$ pip3 install --user ripe.atlas.cousteau      # for creating measurements
```

You'll also probably need either the IANA root or the Yeti root:

```
$ wget -O iana-root.txt ftp://rs.internic.net/domain/named.root 
$ wget -O yeti-root.txt https://raw.githubusercontent.com/BII-Lab/Yeti-Project/master/domain/named.cache
```

Finally, you will need to set your RIPE Atlas key in the
`atlaskeys.py` file.

You can then start a measurement using one of your root hints:

```
$ python3 shrugd-create.py iana-root.txt
```

## Background & Overview

Currently (2015-Q4) the RIPE Atlas probes have two ways to perform DNS
lookups:

1. They can do a lookup using the local resolver of the probe's
   network, or
2. The RIPE Atlas central server can perform DNS lookups before
   sending a measurement to the probe.

While this is satisfactory for most experiments, in some cases more
control of the resolution process would be desirable. For example, the
Yeti Project (https://yeti-dns.org/) uses an different set of root
hints and needs to kick off resolution differently.

Fortunately, the RIPE Atlas probes are quite flexible and can send
DNS packets with almost arbitrary contents. The approach in shrugd is
to emulate the DNS resolution process by sending packets similar to
the ones that a real DNS resolver would use.

## Details

The software uses the RIPE Atlas streaming API. This returns the
results from each measurement as they complete. In this way it
performs somewhat like a real resolver in that packets are sent as
needed and responses received asynchronously and processed in real
time.

The basic approach is to start at the top of the DNS hierarchy (the
root) and then progress down label by label until an answer for the
question asked is received. Basically this works like this:

1. Send a query for the desired name to each of the IP addresses in
   the hints.
2. When the first reply for the current level completes, see if an
   answer is in the reply. If so, then we are done!
3. If the first reply contains no answer, but does contain an
   authority section with NS records, then get the addresses for those
   NS records and send a query for the desired name to each of those
   IP addresses. Goto step #2.

In step #3, we use the IP addresses listed in the additional section
as the IP addresses for our NS servers, if they are present (this is
glue). If there is no glue (for example if the NS servers are
out-of-bailiwick), then shrugd looks up the IP addresses locally using
the local DNS resolver. It is possible to perform full recursion to
get this information, but this is a simplifying step and makes the
resolution much more straightforward.

This process performs a superset of what a normal resolver will do.
Firstly, a resolver will typically not send the query to all authority
servers at a given level of the hierarchy. Secondly, a real resolver
will typically have most of the information cached very quickly -
certainly the root and TLD name servers. Thirdly, a real resolver will
use RTT information about IP addresses to prefer specific servers.

We use the superset since we can't know the cache behavior. What we
can do is look at the full set of results and make some analysis about
possible resolver behavior, setting lower-bounds and upper-bounds on
performance, and making guesses about expected results.

Right now probe selection is out of scope, but the measurement can be
conducted separately on different probes as desired.
