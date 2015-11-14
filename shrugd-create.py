import sys
import ripe.atlas.cousteau
from atlaskeys import create_key

# get the list of IP addresses from a hints file
if len(sys.argv) != 2:
    sys.stderr.write("Syntax: " + sys.argv[0] + " hints.txt\n")
    sys.exit(1)

# get IP addresses to start from (root servers) with a horrible hack
f = open(sys.argv[1])
dns_server_ips = [ ]
for line in f.readlines():
    line = line.strip()
    # skip blank lines
    if line == '':
        continue
    # skip comments
    if line[0] == ';':
        continue
    # check for A/AAAA records
    info = line.split()
    if info[-2] in ('A', 'AAAA'):
        dns_server_ips.append(info[-1])
        
# DNS query properties
query_argument = "wide.ad.jp"
query_type = "AAAA"
dnssec_ok = True
set_nsid_bit = True

def ip_address_family(ip_addr):
    """Return whether an IP address is IPv4 or IPv6"""
    if ':' in ip_addr:
        return 6
    else:
        return 4

dns_measurements = []
for ip_addr in dns_server_ips:
    dns_query = ripe.atlas.cousteau.Dns(
        target=ip_addr,
        af=ip_address_family(ip_addr),
        query_argument=query_argument,
        query_type=query_type,
        query_class="IN",
        set_nsid_bit=set_nsid_bit,
        udp_payload_size=4096,
        description="shrugd " + query_argument + "/" + query_type
    )
    dns_measurements.append(dns_query)

# XXX: possibly should at least pick good IPv6 servers when querying over IPv6
source = ripe.atlas.cousteau.AtlasSource(type="area", value="WW", requested=1)

atlas_request = ripe.atlas.cousteau.AtlasCreateRequest(
    key=create_key,
    measurements=dns_measurements,
    sources=[source],
    is_oneoff=True
)
(is_success, response) = atlas_request.create()
if is_success:
    print("worked, IDs: %s" % response)
else:
    print("did not work: %s" % response)

