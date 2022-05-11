from adblockparser import AdblockRules
from trackingprotection_tools import DisconnectParser
import os
import sys
import json
from os.path import join, sep, isfile, basename, dirname, realpath
import pickle
from tld import get_fld
from whotracksme.data import load_tracker_db

with open('helpers/entities.pkl', 'rb') as handle:
    entities = pickle.load(handle)
with open('helpers/sniffer_dict.pkl', 'rb') as handle:
    sniffer_dict = pickle.load(handle)

def read_ab_rules_from_file(filename):
    filter_list = set()
    for l in open(filename):
        if len(l) == 0 or l[0] == '!':  # ignore these lines
            continue
        else:
            filter_list.add(l.strip())
    return filter_list

def get_adblock_rules():
    raw_easylist_rules = read_ab_rules_from_file("blocklists/easylist.txt")
    raw_easyprivacy_rules = read_ab_rules_from_file("blocklists/easyprivacy.txt")
    # raw_ublock_rules = read_ab_rules_from_file("blocklists/adblock_blacklist_white.txt")

    print ("Loaded %s from EasyList, %s rules from EasyPrivacy" %
           (len(raw_easylist_rules), len(raw_easyprivacy_rules)))
    #        len(raw_ublock_rules)))
    print('Finished initialization')
    easylist_rules = AdblockRules(raw_easylist_rules)
    easyprivacy_rules = AdblockRules(raw_easyprivacy_rules)
    # ublock_rules = AdblockRules(raw_ublock_rules)
    # return easylist_rules, easyprivacy_rules, ublock_rules
    disconnect_blocklist = DisconnectParser(blocklist = "blocklists/disconnect.json")
    return easylist_rules, easyprivacy_rules, disconnect_blocklist
try:
    from functools import lru_cache
except ImportError:
    from functools32 import lru_cache

@lru_cache(maxsize=100000)
def easylist_rules_should_block(easylist_rules, x):
    return easylist_rules.should_block(x, {'third-party': True})


@lru_cache(maxsize=100000)
def easyprivacy_rules_should_block(easyprivacy_rules, x):
    return easyprivacy_rules.should_block(x, {'third-party': True})

def disconnect_rules_should_block(disconnect_rules, x):
    return disconnect_rules.should_block(x)

def add_adblocked_status(df):
    easylist_rules, easyprivacy_rules, disconnect_rules = get_adblock_rules()
    col = "sniffer"
    df['easylist_blocked'] = df[col].map(
        lambda x: easylist_rules_should_block(easylist_rules, x))
    df['easyprivacy_blocked'] = df[col].map(
        lambda x: easyprivacy_rules_should_block(easyprivacy_rules, x))
    df['disconnect_blocked'] = df[col].map(
        lambda x: disconnect_rules_should_block(disconnect_rules, x))
    df['is_blocked'] = df['easylist_blocked'] | df['easyprivacy_blocked'] | df['disconnect_blocked']

def add_rank_col(initial_hostname, domain_col_name, _df):
    _df[domain_col_name] = _df[initial_hostname].map(get_rank)

def get_rank(initial_hostname):
    return ranks[initial_hostname]

def get_initiators(row):
    initiators = set()
    req_initiators = row['request']['initiators']
    for initiator in req_initiators:
        initiator_domain = get_domain(initiator)
        initiators.add(initiator_domain)
    return initiators

def add_sniffer_domain_col(sniffer, domain_col_name, _df):
    _df[domain_col_name] = _df[sniffer].map(get_domain)

def get_domain(url):
    try:
        domain_name = get_fld(url)
    except:
        domain_name = url
    return domain_name

def score_first_party(fp, rank_weight=1):
    """ Weight of 1/(rank of first_party) """
    return 1.0/float(fp)**rank_weight

def get_prominence_for_tp(visit_ranks):
    return sum([score_first_party(x) for x in visit_ranks])

def find_prominence(df):
    prominence_results = []
    trackers_list = df.request_url_domain.unique()
    for tracker in trackers_list:
        rank_of_sites = df[df.request_url_domain==tracker].drop_duplicates(['initial_hostname', 'search_type', 'request_url_domain']).rank_of_site.tolist()
        prominence = get_prominence_for_tp(rank_of_sites)
        prominence_result = (tracker,prominence, len(rank_of_sites))
        prominence_results.append(prominence_result)
    return prominence_results

def is_req_off_site_direction(row):
    if is_iframe_req_domain_same(row['last_page_domain_iframe'], row['request_url_domain']):
        return True
    if belong_to_same_entity(row['request_url_domain'], row['last_page_domain_iframe']):
        return True
# Sample case: zoho.com and zoho.eu
    if matched_domains(row['request_url_domain'], row['last_page_domain']):
        return True
    return False

def is_iframe_req_domain_same(last_page_domain_iframe, request_url_domain):
    if last_page_domain_iframe == request_url_domain:
        return True
    return False

def belong_to_same_entity(request_url_domain, last_page_domain):
    page_entity = get_entity(last_page_domain)
    req_entity = get_entity(request_url_domain)
    if page_entity != '' and req_entity !='' and page_entity == req_entity:  
        return True
    return False

def matched_domains(request_url_domain, last_page_domain):
    import tldextract
    req_domain_without_suffix = tldextract.extract(request_url_domain)[1]
    last_page_domain_without_suffix = tldextract.extract(last_page_domain)[1]
    if req_domain_without_suffix == last_page_domain_without_suffix:
        return True
    return False

def get_entity(request_url_domain):
    for entity, properties in entities.items():
        if request_url_domain in properties:
            return entity
    return ''

def get_sniffs(initial_hostname):
    return sniffer_dict[initial_hostname]
    
def check_sniff_initiators(row):
    sniff_initiator_domains = []
    sniff_initiators = row['sniff_initiators']
    req_domain = row['request_url_domain']
    if req_domain in sniff_initiators:
        return True
    for sniff_initiator_domain in sniff_initiators:
        belongs_to_same_entity = belong_to_same_entity(req_domain, sniff_initiator_domain)
        if belongs_to_same_entity:
            return True
    return False
