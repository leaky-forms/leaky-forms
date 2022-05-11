import json
from tld import get_fld

f = open ('entities.json', "r")
entities = json.loads(f.read())

def get_initiators(initiators):
    initiators = set()
    req_initiators = initiators
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

def get_req_off_site_direction(last_page_domain_iframe, request_url_domain, last_page_domain):
    if is_iframe_req_domain_same(last_page_domain_iframe, request_url_domain):
        return True
    if belong_to_same_entity(request_url_domain, last_page_domain_iframe):
        return True
# Sample case: zoho.com and zoho.eu
    if matched_domains(request_url_domain, last_page_domain):
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
    entity = entities.get(request_url_domain)
    try:
        if 'displayName' in entity:
            return entity['displayName']
    except:
        return ''
    return ''

# def get_sniffs(initial_hostname):
#     return sniffer_dict[initial_hostname]

def check_sniff_initiators(sniff_initiators, request_url_domain):
    sniff_initiator_domains = []
    sniff_initiators = sniff_initiators
    req_domain = request_url_domain
    if req_domain in sniff_initiators:
        return True
    for sniff_initiator_domain in sniff_initiators:
        belongs_to_same_entity = belong_to_same_entity(req_domain, sniff_initiator_domain)
        if belongs_to_same_entity:
            return True
    return False
