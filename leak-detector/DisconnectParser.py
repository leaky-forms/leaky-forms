import json
import os
from collections import Counter
from urllib.parse import urlparse

import requests
from domain_utils import domain_utils as du

DNT_TAG = 'dnt'
FINGERPRINTING_TAG = 'fingerprinting'
CRYPTOMINING_TAG = 'cryptominer'
SESSION_REPLAY_TAG = 'session-replay'
PERFORMANCE_TAG = 'performance'
DISCONNECT_TAGS = {
    FINGERPRINTING_TAG, CRYPTOMINING_TAG, SESSION_REPLAY_TAG, PERFORMANCE_TAG
}
ALL_TAGS = DISCONNECT_TAGS.union({DNT_TAG})


class DisconnectParser(object):
    """A parser for the Disconnect list.

    This partser is meant to use the list as it is used in Firefox's URL
    classifier. This does not necessarily match the implementation of
    Disconnect's own extension or any other consumer of the Disconnect list"""
    def __init__(self, blocklist=None, entitylist=None,
                 blocklist_url=None, entitylist_url=None,
                 disconnect_mapping=None, disconnect_mapping_url=None,
                 categories_to_exclude=[], verbose=False):
        """Initialize the parser.

        Parameters
        ----------
        blocklist : string
            The file location of the blocklist. Either this or `blocklist_url`
            must be specified.
        entitylist : string (optional)
            The file location of the entitylist.
        blocklist_url : string
            A URL where the blocklist can be fetched. Either this or
            `blocklist` must be specified.
        entitylist_url : string (optional)
            A URL where the entitylist can be fetched. This cannot be
            used alongside `entitylist`.
        disconnect_mapping : string (optional)
            A file location of the disconnect category remapping file in json
            format.
        disconnect_mapping_url : string (optional)
            A URL where the disconnect category remapping file can be found.
            This cannot be used alongside `disconnect_mapping`.
        categories_to_exclude : list (optional)
            A list of list categories to exclude. Firefox currently excludes
            the `Content` category by default. (default empty list)
        verbose : boolean
            Set to True to print list parsing info.
        """
        self.verbose = verbose
        self._exclude = set([x.lower() for x in categories_to_exclude])

        # Remapping
        self._disconnect_mapping = self._load_list(
            disconnect_mapping, disconnect_mapping_url)
        self._should_remap = self._disconnect_mapping is not None

        # Blocklist
        self._raw_blocklist = self._load_list(blocklist, blocklist_url)
        if self._raw_blocklist is None:
            raise ValueError(
                "Unable to load blocklist. Did you specify a valid list "
                "location in `blocklist` or `blocklist_url`?"
            )
        rv = self._parse_blocklist(self._raw_blocklist)
        (self._categorized_blocklist,
         self._tagged_domains,
         self._company_classifier) = rv
        self._blocklist = self._flatten_blocklist(self._categorized_blocklist)

        # Entitylist
        self._raw_entitylist = self._load_list(entitylist, entitylist_url)
        if self._raw_entitylist is not None:
            self._entitylist = self._parse_entitylist(self._raw_entitylist)

    def _load_list(self, location, network_location):
        """Load the list from the disk or network and return a json object"""
        if location is not None and network_location is not None:
            raise ValueError(
                "Invalid combination of arguments. "
                "You must not specify both a local and network location of "
                "the same list. Choose one of the following: %s and %s." %
                (location, network_location)
            )
        if location is not None:
            with open(os.path.expanduser(location), 'r') as f:
                json_list = json.load(f)
            return json_list
        if network_location is not None:
            resp = requests.get(network_location)
            if resp.status_code != 200:
                raise RuntimeError(
                    "Bad status code while requesting %s (code: %s)." %
                    (network_location, resp.status_code)
                )
            return json.loads(resp.content.decode('utf-8'))
        return

    def _remap_disconnect(self, domain):
        """Remap the "Disconnect" category

        This contains a bunch of hardcoded logic for remapping the Disconnect
        category as specified here:
            https://github.com/mozilla-services/shavar-prod-lists#blacklist

        Parameters
        ----------
        domain : string
            Domain to remap using the remapping file.

        Returns
        -------
        string : Category from the remapping file.

        Raises
        ------
        ValueError
            If `domain` not found in remapping or `domain` is remapped to a
            non-existent category.
        """
        try:
            category = self._disconnect_mapping[domain]
        except KeyError:
            raise ValueError(
                "Blocklist contains block rule %s under the "
                "Disconnect category, but the rule is not "
                "found in the given Disconnect mapping file."
                % domain
            )
        if category not in self._all_list_categories:
            raise ValueError(
                "Remapping file attempts to remap to an "
                "unexpected category: %s. Supported categories: %s"
                % (category, self._all_list_categories)
            )
        return category

    def _is_domain_key(self, key):
        """Return `True` if the key appears to be a domain key

        Unfortunately the list does not currently provide a structured way to
        differentiate between sub-category tags (like `fingerprinting`) from
        the lists of resources that belong to an organization. We use the
        heuristic of whether the key starts with http or ends in a slash to
        mark resource lists.
        """
        return key not in ALL_TAGS

    def _parse_blocklist(self, blocklist):
        """Parse raw blocklist into a format that's easier to work with"""
        if self.verbose:
            print("Parsing raw list into categorized list...")

        collapsed = dict()
        company_classifier = dict()
        self._all_list_categories = set(blocklist['categories'].keys())
        for category in self._all_list_categories:
            collapsed[category] = set()

        tagged_domains = dict()
        remapping_count = Counter()
        for cat in blocklist['categories'].keys():
            for item in blocklist['categories'][cat]:
                for org, urls in item.items():
                    # Parse out sub-category. The way the list is structured,
                    # we must first iterate through all items to gather
                    # the categories and then iterate again to apply these
                    # categories to domains. Categories are assumed to apply to
                    # all resources in an organization.
                    tags = set()
                    for k, v in urls.items():
                        if self._is_domain_key(k):
                            continue
                        if k in DISCONNECT_TAGS:
                            if v == "true":
                                tags.add(k)
                            continue
                        elif k == DNT_TAG:
                            tags.add(v)
                            continue
                        raise ValueError(
                            "Unsupported record type %s in organization %s. "
                            "This likely means the list changed and the "
                            "parser should be updated." % (k, org))
                    for url, domains in urls.items():
                        if not self._is_domain_key(url):
                            continue
                        for domain in domains:
                            if len(domain) == 1:
                                raise ValueError(
                                    "Unexpected domain of length 1 in "
                                    "resource list %s under organization %s. "
                                    "This likely means the parser needs to be "
                                    "updated due to a list format change." %
                                    (domains, org))
                            for tag in tags:
                                if tag not in tagged_domains:
                                    tagged_domains[tag] = set()
                                tagged_domains[tag].add(domain)
                            if self._should_remap and cat == 'Disconnect':
                                new_cat = self._remap_disconnect(domain)
                                collapsed[new_cat].add(domain)
                                remapping_count[new_cat] += 1
                            collapsed[cat].add(domain)
                            company_classifier[domain] = org
        if self.verbose:
            for category, count in remapping_count.items():
                print("Remapped %d domains from Disconnect to %s" % (
                    count, category))
        return collapsed, tagged_domains, company_classifier

    def _flatten_blocklist(self, blocklist):
        """Generate a flattened version of the blocklist category map"""
        if self.verbose:
            print("Parsing categorized list into single blocklist...")
        out = set()
        for category, domains in self._categorized_blocklist.items():
            if category.lower() in self._exclude:
                if self.verbose:
                    print("Skipping %s" % category)
                continue
            if self._should_remap and category == 'Disconnect':
                if self.verbose:
                    print("Skipping Disconnect as it is remapped")
                continue
            if self.verbose:
                print("Added %i domains for category %s" % (
                    len(domains), category))
            out = out.union(domains)
        return out

    def _parse_entitylist(self, entitylist):
        """Parse raw entitylist into a format that's easier to work with"""
        out = dict()
        for org in entitylist.keys():
            for url in entitylist[org]['properties']:
                out[url] = entitylist[org]['resources']
        return out

    def should_whitelist(self, url, top_url):
        """Check if `url` is whitelisted on `top_url` due to the entitylist

        Parameters
        ----------
        url : string
            The URL or hostname to classify.
        top_url : string
            The URL or hostname of the top-level page on which `url` was loaded

        Returns
        -------
        boolean : True if the url would have been whitelisted by the entitylist
        """
        if not url.startswith('http'):
            url = 'http://' + url
        if not top_url.startswith('http'):
            top_url = 'http://' + top_url
        top_host = urlparse(top_url).hostname
        top_ps1 = du.get_ps_plus_1(top_url)
        url_host = urlparse(url).hostname
        url_ps1 = du.get_ps_plus_1(url)
        if top_host in self._entitylist:
            resources = self._entitylist[top_host]
        elif top_ps1 in self._entitylist:
            resources = self._entitylist[top_ps1]
        else:
            return False
        return url_host in resources or url_ps1 in resources

    def should_block_with_match(self, url, top_url=None):
        """Check if Firefox's Tracking Protection would block this request.

        The return value includes the matching rule and whether or not the
        `url` was explicitly blacklisted, whitelisted, or just not found.

        Firefox blocks domains from the Disconnect list following the
        Safebrowsing parsing rules detailed here:
        https://developers.google.com/safe-browsing/v4/urls-hashing#suffixprefix-expressions

        Parameters
        ----------
        url : string
            The URL or hostname to classify.
        top_url : string
            (optional) The URL or hostname of the top-level page on which `url`
            was loaded. If this is not provided, the entitylist is not checked.

        Returns
        -------
        string : `blacklisted`, `whitelisted`, or None
        string : The matching domain (only supported for blocking) or None
        """
        if not url.startswith('http'):
            url = 'http://' + url

        if top_url is not None and self.should_whitelist(url, top_url):
            return 'whitelisted', None

        # Check exact hostname
        hostname = urlparse(url).hostname
        if hostname in self._blocklist:
            return 'blacklisted', hostname

        # Skip IP address
        if du.is_ip_address(hostname):
            return None, None

        # Check up to four hostnames formed by starting with the last five
        # components and successively removing the leading component
        # NOTE: The top-level domain should be skipped, but this is currently
        # not implemented in Firefox. See: Bug 1203635.
        hostname = '.'.join(hostname.rsplit('.', 5)[1:])
        # ps1 = ps1 = du.get_ps_plus_1(url)  # blocked on Bug 1203635
        count = 0
        while hostname != '':
            count += 1
            if count > 4:
                return None, None
            if hostname in self._blocklist:
                return 'blacklisted', hostname
            # Skip top-level domain (blocked on Bug 1203635)
            # if hostname == ps1:
            #     return None, None
            try:
                hostname = hostname.split('.', 1)[1]
            except IndexError:
                return None, None
        return None, None

    def should_block(self, url, top_url=None):
        """Check if Firefox's Tracking Protection would block this request

        Parameters
        ----------
        url : string
            The URL or hostname to classify.
        top_url : string
            (optional) The URL or hostname of the top-level page on which `url`
            was loaded. If this is not provided, the entitylist is not checked.

        Returns
        -------
        boolean : True if the url would have been blocked by Disconnect.
        """
        result, match = self.should_block_with_match(url, top_url)
        return result == 'blacklisted'

    def contains_domain(self, hostname):
        """Returns True if the Disconnect list contains that exact hostname"""
        return hostname in self._blocklist

    def contains_ps1(self, hostname):
        """Returns True if the Disconnect list contains any domains from ps1"""
        if not hostname.startswith('http'):
            hostname = 'http://' + hostname
        return du.get_ps_plus_1(hostname) in self._blocklist

    def get_matching_domains(self, hostname):
        """Returns all domains that match or are subdomains of hostname"""
        return [x for x in self._blocklist if x.endswith(hostname)]

    def get_domains_with_category(self, categories,
                                  skip_disconnect_if_remapped=True):
        """Returns all domains with the top-level categories

        Parameters
        ----------
        categories : string or list of strings
            One or more top-level categories to pull from the list
        skip_disconnect_if_remapped : boolean, optional
            Skip retrieval of Disconnect domains if the category is already
            remapped. (default True)

        Returns
        -------
        set : All domains / rules under `categories`.

        Raises
        ------
        KeyError
            If a requested category isn't found in the blocklist.
        """
        if isinstance(categories, str):
            categories = [categories]
        out = set()
        for category in categories:
            if self._should_remap and category == 'Disconnect':
                continue
            out.update(self._categorized_blocklist[category])
        return out

    def get_domains_with_tag(self, tags):
        """Returns all domains with the top-level categories

        Parameters
        ----------
        tags : string or list of strings
            One or more top-level sub-category tags to pull from the list.
            To specify `dnt` tags, use the type: `eff` or `w3c`. This will not
            throw an exception if a key is not found.

        Returns
        -------
        set : All domains / rules under `categories`.
        """
        if isinstance(tags, str):
            tags = [tags]
        out = set()
        for tag in tags:
            out.update(self._tagged_domains.get(tag, {}))
        return out