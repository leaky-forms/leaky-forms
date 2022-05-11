import sys
from multiprocessing import Pool, cpu_count
from os.path import basename, join
from glob import glob
from LoginLeakDetector import detect_leaks_in_json
from time import time
import pandas as pd
import pickle
from CrawStatisticsChecker import get_urls_and_times_for_email_password_fields


def detect_leaks(crawl_dir):
    crawl_name = basename(crawl_dir)
    print("Will search leaks in %s" % (crawl_name))
    counter = 0
    start_time = time()
    all_site_leaks = []
    all_js_leaks = []
    n_leaky_sites = 0
    all_sniffs = set()
    crawl_details = []
    fill_timestamps, last_page_urls, filled_websites, cmp_websites, xpath_els, ids_els =\
        get_urls_and_times_for_email_password_fields(crawl_dir + '.log')
    t_after_log_procs = time()
    print("Log processing took %0.1f" % (t_after_log_procs - start_time))
    json_paths = glob(join(crawl_dir, "*_*.json"))
    # json_paths = glob(join(crawl_dir, "www.wisestamp.com_b225.json"))
    # json_paths = json_paths[:1000]
    print("Will process %d jsons" % len(json_paths))
    for path in json_paths:
        crawl_details.append(
            (path, fill_timestamps, last_page_urls,
             filled_websites, cmp_websites, xpath_els, ids_els))

    with Pool(processes=cpu_count()) as pool:
        for leaks in pool.imap_unordered(detect_leaks_in_json, crawl_details):
            counter += 1
            if leaks is None:
                continue
            site_leaks, sniffs, js_cookie_leaks = leaks
            all_sniffs.update(sniffs)
            if site_leaks is not None and len(site_leaks):
                # print('Detected leak(s) on', site_leaks[0][7])  # initial host
                all_site_leaks += site_leaks
                n_leaky_sites += 1
            elif js_cookie_leaks is not None and len(js_cookie_leaks):
                print('Detected leaks in js_cookies only', js_cookie_leaks)
                all_js_leaks += js_cookie_leaks
            if not counter % 100:
                passed_time = time() - start_time
                print(
                    "Processed %d jsons. Found %d leaks on %d sites in %0.1fs"
                    % (counter, len(all_site_leaks),
                        n_leaky_sites, passed_time))

    t_leak_end = time()
    leak_detection_time = t_leak_end - t_after_log_procs
    print("FINISHED! Processed %d jsons. Found %d leaks on %d sites in %0.1f" %
          (counter, len(all_site_leaks), n_leaky_sites, leak_detection_time))

    df = pd.DataFrame(all_site_leaks, columns=[
        'search', 'search_type', 'encoding', 'leak_type', 'final_url',
        'final_url_domain', 'initial_url', 'initial_hostname',
        'last_page_domain', 'request_url', 'request_url_domain',
        'third_party_req', 'easy_list_blocked', 'easy_privacy_blocked',
        'disconnect_blocked', 'radar_blocked', 'whotracksme_blocked', 'tracker_owner',
        'is_req_sent_after_fill', 'request_timestamp',
        'field_fill_time', 'is_any_initiator_third_party', 'referrer',
        'was_cmp_detected', 'is_any_field_filled', 'request', 'request_type', 'category', 'rank_of_site', 'req_initiators', 'xpath', 'id', 'is_same_party', 'req_domain_entity', 'last_page_url', 'req_domain_category'])

    with open("%s_js_cookie_leaks.pkl" % crawl_name, 'wb') as handle:
        pickle.dump(all_js_leaks, handle)

    # Store data (serialize)
    with open("%s_sniffs.pkl" % crawl_name, 'wb') as handle:
        pickle.dump(all_sniffs, handle)
    email_sniffed_set = set()
    pwd_sniffed_set = set()
    for leak_type, initial_hostname, __, __, __ in all_sniffs:
        if leak_type == 'email':
            email_sniffed_set.add(initial_hostname)
        if leak_type == 'pwd':
            pwd_sniffed_set.add(initial_hostname)

    df['email_sniffed'] = df.initial_hostname.map(
        lambda x: x in email_sniffed_set)
    df['pwd_sniffed'] = df.initial_hostname.map(
        lambda x: x in pwd_sniffed_set)

    df.to_pickle("%s_leaks_df.pkl" % crawl_name)

if __name__ == '__main__':
    if len(sys.argv) >= 2:  # no arg means process all crawls
        detect_leaks(sys.argv[1])