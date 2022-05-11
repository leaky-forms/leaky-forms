from adblockparser import AdblockRules
from trackingprotection_tools import DisconnectParser
import os
import sys
import json
from os.path import join, sep, isfile, basename, dirname, realpath
from collections import defaultdict
from whotracksme.data import load_tracker_db

req_types = [
    "script",
    "image",
    "stylesheet",
    "object",
    "xmlhttprequest",
    "object-subrequest",
    "subdocument",
    "document",
    "elemhide",
    "other",
    "background",
    "xbl",
    "ping",
    "dtd",
    "media",
    "third-party",
    "match-case",
    "collapse",
    "donottrack",
    "websocket",
]
def get_whotracksme_trackers():
    # Keep track of normalized "app" name for each tracker domain. A given "app"
    # such as "doubleclick" can use several domains: 2mdn.net, doubleclick.net, etc.
    tracker_domains_to_app = {}

    # Load trackers and group them by category
    sql_query = """
      SELECT categories.name, tracker, domain FROM tracker_domains
      INNER JOIN trackers ON trackers.id = tracker_domains.tracker
      INNER JOIN categories ON categories.id = trackers.category_id;
    """
    with load_tracker_db() as connection:
        for (category, tracker, domain) in connection.execute(sql_query):
            tracker_domains_to_app[domain] = tracker
    return tracker_domains_to_app

def get_radar_trackers():
    all_files = []
    all_domains_entities = dict()
    path = "blocklists/domains/"
    for root, dirs, files in os.walk(path):
        all_files.extend([my_file for my_file in files])
        for name in files:
            if name.endswith((".json")):
                full_path = os.path.join(root, name)

                with open(full_path) as f:
                    trackers_dict = json.load(f)
                    try:
                        all_domains_entities[trackers_dict['domain']] = trackers_dict['owner']['displayName']
                    except:
                        all_domains_entities[trackers_dict['domain']] = ''
    return all_domains_entities

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

    print ("Loaded %s from EasyList, %s rules from EasyPrivacy" %
           (len(raw_easylist_rules), len(raw_easyprivacy_rules)))
    print('Finished initialization')
    easylist_rules = AdblockRules(raw_easylist_rules)
    easyprivacy_rules = AdblockRules(raw_easyprivacy_rules)
    disconnect_blocklist = DisconnectParser(blocklist = "blocklists/disconnect.json")
    return easylist_rules, easyprivacy_rules, disconnect_blocklist
try:
    from functools import lru_cache
except ImportError:
    from functools32 import lru_cache

def disconnect_rules_should_block(disconnect_blocklist, request_url):
    return disconnect_blocklist.should_block(request_url)

@lru_cache(maxsize=100000)
def easylist_rules_should_block(easylist_rules, request_url, domain, req_type):
    if req_type in req_types:
        options = {req_type: True, 'domain': domain, 'third-party': True}
    else:
        options = {'domain': domain, 'third-party': True}
    return easylist_rules.should_block(request_url, options)


@lru_cache(maxsize=100000)
def easyprivacy_rules_should_block(easyprivacy_rules, request_url, domain, req_type):
    if req_type in req_types:
        options = {req_type: True, 'domain': domain, 'third-party': True}
    else:
        options = {'domain': domain, 'third-party': True}
    return easyprivacy_rules.should_block(request_url, options)