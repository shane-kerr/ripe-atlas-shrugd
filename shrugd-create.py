import ripe.atlas.cousteau
from atlaskeys import create_key

# DNS query properties
query_argument = "wide.ad.jp"
query_type = "AAAA"
dnssec_ok = True
set_nsid_bit = True

# IP addresses to start from
dns_server_ips = [ 
    "199.7.91.13", "2001:500:2d::d", # D.ROOT-SERVERS.NET
    "192.203.230.10",                # E.ROOT-SERVERS.NET
]

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
        description="shrugd " + query_argument + "/" 
    )
    dns_measurements.append(dns_query)
    break

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
    print("did not work")

