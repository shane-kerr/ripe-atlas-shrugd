import argparse
import random

import ripe.atlas.cousteau
import ripe.atlas.sagan

from atlaskeys import create_key

def ip_address_family(ip_addr):
    """Return whether an IP address is IPv4 or IPv6"""
    return 6 if ':' in ip_addr else 4

def create_measurement_from_specificiation(query_argument, ip_addr,
        query_type = "AAAA", dnssec_ok = True, set_nsid_bit = True):
    # XXX: possibly should at least pick good IPv6 servers when querying
    # over IPv6
    atlas_source_kwargs = {
        'type': "area",
        'value': "WW",
        'requested': 1,
        'tags': {
            'include': ["system-anchor"]
        }
    }
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

    source = ripe.atlas.cousteau.AtlasSource(**atlas_source_kwargs)
    atlas_request = ripe.atlas.cousteau.AtlasCreateRequest(
        key=create_key,
        measurements=[dns_query],
        sources=[source],
        is_oneoff=True
    )
    (is_success, response) = atlas_request.create()
    return response if is_success else None

def on_result_response(*args):
    """
    Function that will be called every time we receive a new result.
    Args is a tuple, so you should use args[0] to access the real message.
    Returns {rcode, answer, authority, additional}
    """
    result_response = {
        'rcode': [],
        'answers': [],
        'authorities': [],
        'additionals': []
    }
    my_dns_result = ripe.atlas.sagan.DnsResult(args[0])
    for response in my_dns_result.responses:
        result_response['rcode'].append(response.abuf.header.return_code)
        if hasattr(response.abuf, 'answers'):
            for answers_answer in response.abuf.answers:
                record = set(answers_answer.name, answers_answer.data)
                result_response['answers'].append(record)
        if hasattr(response.abuf, 'authorities'):
            for authorities_answer in response.abuf.authorities:
                record = set(authorities_answer.type)
                result_response['authorities'].append(record)
        if hasattr(response.abuf, 'additionals'):
            for additional_answer in response.abuf.additionals:
                record = set(additional_answer.type)
                result_response['additionals'].append(record)
    print result_response
    return result_response

def create_hints_dict(hints_file):
    hints_to_return = []
    for line in hints_file.readlines():
        line = line.strip()
        # skip blank lines or comments
        if line == '' or line[0] == ';':
            continue
        # check for A/AAAA records
        info = line.split()
        if info[-2] in ('A', 'AAAA'):
            hints_to_return.append(info[-1])
    return hints_to_return

def main(args):
    hints = create_hints_dict(args.hints)
    msms = []
    for hint in hints:
        msm = create_measurement_from_specificiation("wide.ad.jp", hint,
            query_type = "AAAA", dnssec_ok = True, set_nsid_bit = True)
        msms.append(msm)

    atlas_stream = ripe.atlas.cousteau.AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_stream("result", on_result_response)

    for msm in msms:
        if msm is not None and 'measurements' in msm:
            atlas_stream.start_stream(stream_type="result",
                    msm = msm['measurements'][0])

    atlas_stream.timeout()
    atlas_stream.disconnect()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('hints', nargs='?', type=argparse.FileType('r'))
    args = parser.parse_args()
    main(args)
