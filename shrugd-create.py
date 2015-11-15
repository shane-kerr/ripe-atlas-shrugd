import argparse
import random
import socket
import sys
import csv

import ripe.atlas.cousteau
import ripe.atlas.sagan

from atlaskeys import create_key

class ResolutionCache:
    def __init__(self, outfile):
        self.outfile = outfile
        self.source_probes = None
        self.cache = {
            # zone : answer
        }
        self.measurements = [
        ]
    def add(self, resolution, probe_id, measurement_id, created_timestamp):
        for message_type, messages in resolution.iteritems():
            if message_type == 'rcode':
                self.measurements.append([probe_id, measurement_id,
                        created_timestamp, message_type] + list(messages))
            else:
                for message in messages:
                    if (message_type == 'authorities' and message[0] == 'NS' and
                            message[1] not in self.cache):
                        self.cache[message[1]] = resolution
                    self.measurements.append([probe_id, measurement_id,
                            created_timestamp, message_type] + list(message))
        return
    def check(self, target):
        return target not in self.cache
    def export(self):
        if self.outfile != None:
            with open(self.outfile, 'a') as outfile:
                outcsv = csv.writer(outfile)
                outcsv.writerows(self.measurements)
        return

def ip_address_family(ip_addr):
    """Return whether an IP address is IPv4 or IPv6"""
    return 6 if ':' in ip_addr else 4

def create_measurement_from_specificiation(query_argument, ip_addr,
        query_type = "AAAA", dnssec_ok = True, set_nsid_bit = True):
    # XXX: possibly should at least pick good IPv6 servers when querying
    # over IPv6
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
    atlas_request = ripe.atlas.cousteau.AtlasCreateRequest(
        key=create_key,
        measurements=[dns_query],
        sources=[resolution_cache.source_probes],
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
    dns_result = ripe.atlas.sagan.DnsResult(args[0])
    for response in dns_result.responses:
        result_response['rcode'].append(response.abuf.header.return_code)
        if hasattr(response.abuf, 'answers'):
            for answers_answer in response.abuf.answers:
                record_tuple = tuple([answers_answer.type, answers_answer.name,
                        answers_answer.address])
                result_response['answers'].append(record_tuple)
        if hasattr(response.abuf, 'authorities'):
            for authorities_answer in response.abuf.authorities:
                if authorities_answer.type == 'NS':
                    record_tuple = tuple([authorities_answer.type,
                            authorities_answer.name, authorities_answer.target])
                    result_response['authorities'].append(record_tuple)
                elif authorities_answer.type == 'SOA':
                    record_tuple = tuple([authorities_answer.type,
                            authorities_answer.serial])
                    result_response['authorities'].append(record_tuple)
        if hasattr(response.abuf, 'additionals'):
            for additional_answer in response.abuf.additionals:
                record_tuple = tuple([additional_answer.type,
                        additional_answer.name, additional_answer.address])
                result_response['additionals'].append(record_tuple)

    resolution_cache.add(result_response, dns_result.probe_id,
            dns_result.measurement_id, dns_result.created_timestamp)

    if len(result_response['answers']) > 0:
        for answer in result_response['answers']:
            print (("Found answer record for question (%s) of address (%s) "
                    "with type (%s) with name (%s)") % (question, answer[1],
                    answer[0], answer[2]))
        resolution_cache.export()
        sys.exit()
    elif 'NXDOMAIN' in result_response['rcode']:
        print ("Found NXDOMAIN for name (%s), halting." % (question))
        resolution_cache.export()
        sys.exit()
    elif (len(result_response['answers']) == 0 and
            (True in [True for aa in result_response['authorities']
            if aa[0] == 'SOA'])):
        print (("Found an authoritative nameserver for question (%s) " +
                "but no record found for type (%s)") % (question, query_type))
        resolution_cache.export()
        sys.exit()
    elif (len(result_response['authorities']) > 0 and
            not resolution_cache.check(result_response['authorities'][0][1])):
        resolution_cache.source_probes = create_source_probes_list('probes',
                dns_result.probe_id)
        create_question(question, result_response['authorities'],
                additional_answers = result_response['additionals'])

def create_question(question, authorities_answer, additional_answers = []):
    print ('Found authorities (%i), choosing one at random' %
            len(authorities_answer))
    relevant_nameserver_at_random = random.choice([aa[2] for aa in
            authorities_answer if aa[0] == 'NS'])
    try:
        relevant_gluerecord_at_random = random.choice([rn[2] for rn in
                additional_answers if rn[1] == relevant_nameserver_at_random])
    except IndexError:
        relevant_gluerecord_at_random = socket.gethostbyname(relevant_nameserver_at_random)

    atlas_stream = ripe.atlas.cousteau.AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_stream("result", on_result_response)
    msm = create_measurement_from_specificiation(question,
            relevant_gluerecord_at_random, query_type = query_type,
            dnssec_ok = True, set_nsid_bit = True)

    if msm != None:
        print ("Created msm #%s for question (%s) to destination (%s)" %
                (msm['measurements'][0], question,
                relevant_gluerecord_at_random))
        atlas_stream.start_stream(stream_type="result",
                msm = msm['measurements'][0])
    else:
        print ("No measurement created, likely due to rate limiting.")

    atlas_stream.timeout()
    atlas_stream.disconnect()

    return

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

def create_source_probes_list(probe_type, probe_value, probe_tags = []):
    atlas_source_kwargs = {
        'type': probe_type,
        'value': probe_value,
        'requested': 1,
        'tags': {
            'include': probe_tags
        }
    }
    return ripe.atlas.cousteau.AtlasSource(**atlas_source_kwargs)

def main(args):
    hints = create_hints_dict(args.hints)
    msms = []

    for hint in hints:
        msm = create_measurement_from_specificiation(args.question, hint,
            query_type = args.query_type, dnssec_ok = True, set_nsid_bit = True)
        if msm != None:
            print ("Created msm #%s for question (%s) to destination (%s)" %
                    (msm['measurements'][0], args.question, hint))
            msms.append(msm)
        else:
            print ("No measurement created, likely due to rate limiting.")

    atlas_stream = ripe.atlas.cousteau.AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_stream("result", on_result_response)

    for msm in msms:
        if msm is not None and 'measurements' in msm:
            atlas_stream.start_stream(stream_type="result",
                    msm = msm['measurements'][0], sendBacklog = True)
    try:
        atlas_stream.timeout()
    except KeyboardInterrupt:
        print "Caught keyboard exit."
    atlas_stream.disconnect()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('question', type=str)
    parser.add_argument('hints', nargs='?', type=argparse.FileType('r'))
    parser.add_argument('--query_type', type=str, default = 'AAAA')
    parser.add_argument('--probe_type', type=str, default = 'area')
    parser.add_argument('--probe_value', type=str, default = 'WW')
    parser.add_argument('--probe_tags', nargs='+', default = ['system-anchor'])
    parser.add_argument('--export', type=str, default = None)
    args = parser.parse_args()

    resolution_cache = ResolutionCache(args.export)
    resolution_cache.source_probes = create_source_probes_list(args.probe_type,
            args.probe_value, args.probe_tags)
    question = args.question
    query_type = args.query_type

    main(args)
