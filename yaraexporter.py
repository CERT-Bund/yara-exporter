#!/usr/bin/env python3
"""
Yaraexporter
------------
This little program exports attributes (regkey, regkey|value, pattern-in-file and mutex) from misp events and creates
yara files that are usable with `Thor <https://www.bsk-consulting.de/apt-scanner-thor/>`_. Only attributes that are not
proposed to delete and marked as 'export to ics' are exported.

This script can be used with different parameters from the cli:

.. code-block:: none

    usage: yaraexporter.py [-h] -u URL [-k] [-s SSL] -a ATTRIBUTE [-f FILE] [-c]
                           [-d] [-i IGNORE]

    Connects to an MISP instance and exports yara rules based on givenattribute
    types.

    optional arguments:
      -h, --help            show this help message and exit
      -u URL, --url URL     The url of the MISP instance.
      -k, --key             Prompts for the API key. If not given read MISP_KEY
                            from env.
      -s SSL, --ssl SSL     Path to certificate file for validation, if not
                            globally trusted.
      -a ATTRIBUTE, --attribute ATTRIBUTE
                            Which attribute to export. (Currently supported:
                            regkey, pattern-in-file, mutex)
      -f FILE, --file FILE  Path to output file for the yara rules. If not given,
                            rules are printed to stdout.
      -c, --compile         Compile the rules and place *.yas next to FILE.
      -d, --debug           Turn on debug mode.
      -i IGNORE, --ignore IGNORE
                            Comma separated list of events to ignore.

    Thanks for using! CERT-Bund, 2017

The preferred way to call this script should be:

.. code-block:: none

    MISP_KEY=Thisisyourmispapikey12345 ./yaraexporter.py [PARAMS]

But you're able to call it with the -k param and enter the api key in the cli:

.. code-block:: none

    ./yaraexporter.py -k -u https://your.misp-instance.com -a mutex
    Enter API Key for https://your.misp-instance.com:


Attribute types
---------------
Regkey and Regkey|value
^^^^^^^^^^^^^^^^^^^^^^^
For the registry yara rules, all attributes containig registry relevant values are exported. While doing so, the hive
part (e.g. HKEY_LOCAL_MACHINE etc.) are cutted, because Thor loads them seperately. Also, the rules containing
'registry' in the name. Apart from that, the rules are similar to the normal pattern-in-file rules.

Mutex
^^^^^
Mutex rules include the parameter 'limit = "Mutex"' in the meta part of the rule to select them for mutex enumeration.

Pattern-in-file
^^^^^^^^^^^^^^^
Nothing special here. Remember not to use too generic values in misp.

Class functions
---------------
"""
import argparse
import getpass
import io
import os
import re

import progressbar
import pymisp
import yara
try:
    from typing import Union
    HAS_TYPING = True
except ImportError:
    # No support for typing (https://docs.python.org/3/library/typing.html)
    HAS_TYPING = False

_AVAILABLETYPES = ['regkey', 'regkey|value', 'pattern-in-file', 'mutex']


class YaraexporterError(Exception):
    """Parent class for Exceptions.

    :param message: Error message"""
    def __init__(self, message: str):
        self.message = message


class NoApiKeyError(YaraexporterError):
    """This is raised if no API key was given.

    :param message: Error message"""
    def __init__(self, message: str):
        YaraexporterError.__init__(self, message)


class AttributeNotSupportedError(YaraexporterError):
    """This is raised if an unsupported attribute type is queried.

    :param message: Error message"""
    def __init__(self, message: str):
        YaraexporterError.__init__(self, message)


class Yaraexporter:
    """Creates a pymisp instance to fetch given attributes and create yara rules from it. This can also be imported to
    other modules.

    :param url: Url to MISP instance.
    :param key: API key
    :param ssl: True for validation, False to skip or path to self-signed cert.
    :param debug: If set to true, it can be used for locating errors.
    :param ignore: Comma separated list of MISP eventIds to ignore."""

    if HAS_TYPING:
        def __init__(self, url: str, key: str, ssl: Union[bool, str]=True, debug: bool=False,
                     ignore: Union[str, None]=None):
            if ssl and not os.path.isfile(ssl):
                ssl = True
            self.debug = debug
            self._debug('Connecting to {}.'.format(url))
            self.misp = pymisp.PyMISP(url=url, key=key, ssl=ssl)
            if ignore:
                self.ignore = ignore.split(',')
            else:
                self.ignore = None
    else:
        def __init__(self, url: str, key: str, ssl=True, debug: bool=False, ignore=None):
            # Python <= 3.5 doesn support typing.Union. This method will be removed
            # when we stop supporting python 3.4
            if ssl and not os.path.isfile(ssl):
                ssl = True
            self.debug = debug
            self._debug('Connecting to {}.'.format(url))
            self.misp = pymisp.PyMISP(url=url, key=key, ssl=ssl)
            if ignore:
                self.ignore = ignore.split(',')
            else:
                self.ignore = None

    def __enter__(self):
        """Needed for 'with'"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Needed for 'with'"""
        os.environ['MISP_KEY'] = 'removed.'

    def _debug(self, string: str) -> None:
        """For debugging."""
        if self.debug:
            print('[DEBUG] {}'.format(string))

    def _debug_and_stop(self, string: str) -> None:
        """For debugging."""
        self._debug(string)
        self.debug = False

    def _search_for_type(self, type_attribute: str) -> list:
        """The actual request to misp. Skip attributes which are proposed for deletion.

        :param type_attribute: MISP event attribute type to search for
        :returns: List of values per event matching type_attribute"""
        results = self.misp.search(type_attribute=type_attribute, deleted=False)
        attribute_values = []

        self._debug('Processing MISP results...')
        bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
        for idx, events in enumerate(results.get('response', None)):
            bar.update(idx)
            event_info = events.get('Event').get('info')
            event_id = events.get('Event').get('id')
            if self.ignore and event_id in self.ignore:
                continue
            attribute_values.append({'info': event_info,
                                     'id': event_id,
                                     'values': []})
            for values in events.get('Event').get('Attribute'):
                # Skip attributed which are proposed to delete
                shadow_attribute = values.get('ShadowAttribute', None)
                if len(shadow_attribute) > 0 and shadow_attribute[0].get('proposal_to_delete', False):
                    continue

                # Skip attributes which are not marked for ids export
                if not values.get('to_ids', None):
                    continue

                if type_attribute in values.get('type'):
                    attribute_values[idx]['values'].append(values.get('value'))
        return attribute_values

    def _create_regkey_rule(self, searchresults: list) -> str:
        """Create regkey rules. Delete symbols, that are not allowed for yara rules and format it according to thor
        manual.

        :param searchresults: Results from MISP search (pymisp.PyMisp().search()
        :returns: yara rules as a string"""
        rules = ''
        bar = progressbar.ProgressBar(max_value=len(searchresults))
        for p, event in enumerate(searchresults):
            eventinfo = re.sub(r'[^\x30-\x7a]', r'', event.get('info')).replace(' ', '_').replace(':', '') \
                .replace('[', '').replace('\\', '').replace(']', '').replace('^', '').replace('@', '').replace('?', '') \
                .replace('>', '').replace('<', '')
            rulename = 'Registry_MISPID_{}_{}'.format(event.get('id'), eventinfo)[0:127]

            rule = 'rule {} {{\n\tmeta:\n\t\t' \
                   'description = "Created with yaraexporter, CERT-Bund 2017."\n\t\t' \
                   'author = "Nils Kuhnert"\n\t\t' \
                   'score = 70\n\t\t' \
                   'reference = {}\n\t' \
                   'strings:\n'.format(rulename, event.get('id'))
            strings = ''
            for idx, value in enumerate(event.get('values')):
                # Remove hive path and apply Thor formatting
                value = re.sub(r'^(HKEY_LOCAL_MACHINE\\|HKEY_CURRENT_USER\\|'
                               r'HKCC\\|HKCR\\|HKLM\\|HKCU\\|\\)(\.|)[A-Za-z0-9\-* ]*\\*', '', value)
                # Remove non ascii chars (illegal characters everywhere...)
                value = re.sub(r'[^\x20-\x7a|]', '', value)

                # Split given value for | in case it is regkey|value
                split_regkey_value = value.split('|')

                # Split the regkey-path in order to allow correct Thor formatting
                split_regkey_path = split_regkey_value[0].split('\\')
                last = len(split_regkey_path) - 2
                regstring = ''

                # For every given string in the path, check if there must be a backslash or semicolon to split
                for idy, path in enumerate(split_regkey_path):
                    path = path.replace('\\', '\\\\').replace('"', '\\"')
                    if idy < last:
                        regstring += '{}\\\\'.format(path)
                    elif idy <= last:
                        regstring += '{};'.format(path)
                    else:
                        regstring += path

                if len(split_regkey_value) > 1:
                    regstring += ';{}'.format(split_regkey_value[1].replace('\\', '\\\\').replace('"', '\\"'))

                if len(regstring) > 0 and ('\\\\' in regstring or ';' in regstring):
                    strings += '\t\t$a{} = "{}"\n'.format(idx, regstring)

            rule += strings + '\tcondition:\n\t\t1 of them\n}\n\n'

            # Skip adding rule to ruleset, if strings is empty (yara error otherwise)
            if 'strings:\n\tcondition:' in rule:
                continue

            # Add rule to ruleset
            rules += rule

            # Update progressbar
            bar.update(p + 1, True)
        return rules

    def _create_pattern_rule(self, searchresults: list) -> str:
        """Create simple pattern matching yara rule

        :param searchresults: Results from MISP search (pymisp.PyMisp().search())
        :returns: yara rules as a string"""
        rules = ''
        bar = progressbar.ProgressBar(max_value=len(searchresults))
        for p, event in enumerate(searchresults):
            eventinfo = re.sub(r'[^\x30-\x7a]', r'', event.get('info')).replace(' ', '_').replace(':', '') \
                .replace('[', '').replace('\\', '').replace(']', '').replace('^', '').replace('@', '').replace('?', '') \
                .replace('>', '').replace('<', '')
            rulename = 'Pattern_MISP_{}_{}'.format(event.get('id'), eventinfo)[0:127]

            rule = 'rule {} {{\n\tmeta:\n\t\t' \
                   'description = "Created with yaraexporter, CERT-Bund 2017."\n\t\t' \
                   'author = "Nils Kuhnert"\n\t\t' \
                   'score = 70\n\t\t' \
                   'reference = {}\n\t' \
                   'strings:\n'.format(rulename, event.get('id'))
            strings = ''
            for idx, value in enumerate(event.get('values')):
                value = value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                strings += '\t\t$a{} = "{}"\n'.format(idx, value)
            rule += strings + '\tcondition:\n\t\t1 of them\n}\n\n'

            if 'strings:\n\tcondition:' in rule:
                continue

            rules += rule
            bar.update(p + 1, True)
        return rules

    def _create_mutex_rule(self, searchresults: list) -> str:
        """Create mutex rule. Double the strings for ascii and wide search.

        :param searchresults: Results from MISP search (pymisp.PyMisp().search())
        :returns: yara rules as a string"""
        rules = ''
        bar = progressbar.ProgressBar(max_value=len(searchresults))
        for p, event in enumerate(searchresults):
            eventinfo = re.sub(r'[^\x30-\x7a]', r'', event.get('info')).replace(' ', '_').replace(':', '') \
                .replace('[', '').replace('\\', '').replace(']', '').replace('^', '').replace('@', '').replace('?', '') \
                .replace('>', '').replace('<', '')
            rulename = 'Mutex_MISP_{}_{}'.format(event.get('id'), eventinfo)[0:127]

            rule = 'rule {} {{\n\tmeta:\n\t\t' \
                   'description = "Created with yaraexporter, CERT-Bund 2017."\n\t\t' \
                   'author = "Yaraexporter, Nils Kuhnert"\n\t\t' \
                   'score = 70\n\t\t' \
                   'reference = {}\n\t\t' \
                   'limit = "Mutex"\n\t' \
                   'strings:\n'.format(rulename, event.get('id'))
            strings = ''
            for idx, value in enumerate(event.get('values')):
                value = re.sub(r'^.*\\', r'', value)
                value = value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
                strings += '\t\t$a{} = "{}" ascii\n'.format(idx, value)
                strings += '\t\t$aw{} = "{}" wide\n'.format(idx, value)
            rule += strings + '\tcondition:\n\t\t1 of them\n}\n\n'

            if 'strings:\n\tcondition:' in rule:
                continue

            rules += rule

            bar.update(p + 1, True)
        return rules

    def get_rules_for_type(self, type_attribute: str) -> str:
        """Sends the request to misp using pymisp api and call the specific rule creation function"""
        rule = ''
        if type_attribute in _AVAILABLETYPES:
            self._debug('Downloading attributes...')
            searchresult = self._search_for_type(type_attribute=type_attribute)
            self._debug('Start processing search results...')
            if type_attribute == 'regkey' or type_attribute == 'regkey|value':
                rule = self._create_regkey_rule(searchresults=searchresult)
            elif type_attribute == 'pattern-in-file':
                rule = self._create_pattern_rule(searchresults=searchresult)
            elif type_attribute == 'mutex':
                rule = self._create_mutex_rule(searchresults=searchresult)
        else:
            raise AttributeNotSupportedError('Attribute {} not supported, yet.'.format(type_attribute))
        return rule


def run() -> None:
    """This is just the basic runner which parses args and delegates to functions"""
    parser = argparse.ArgumentParser(description='Connects to an MISP instance and exports yara rules based on given'
                                                 'attribute types.',
                                     epilog='Thanks for using!\nCERT-Bund, 2017')
    parser.add_argument('-u', '--url', type=str, required=True, help='The url of the MISP instance.')
    parser.add_argument('-k', '--key', dest='prompt', action='store_true',
                        help='Prompts for the API key. If not given read MISP_KEY from env.')
    parser.add_argument('-s', '--ssl', type=str,
                        help='Path to certificate file for validation, if not globally trusted.')
    parser.add_argument('-a', '--attribute', type=str, required=True,
                        help='Which attribute to export. (Currently supported: regkey, pattern-in-file, mutex)')
    parser.add_argument('-f', '--file', type=str,
                        help='Path to output file for the yara rules. If not given, rules are printed to stdout.')
    parser.add_argument('-c', '--compile', dest='compileyara', action='store_true',
                        help='Compile the rules and place *.yas next to FILE.')
    parser.add_argument('-d', '--debug', dest='debug', action='store_true',
                        help='Turn on debug mode.')
    parser.add_argument('-i', '--ignore', type=str, help='Comma separated list of events to ignore.')
    parser.set_defaults(prompt=False, compileyara=False, debug=False)
    args = parser.parse_args()

    # Prompt for api key or get it from env
    if args.prompt:
        key = getpass.getpass(prompt='Enter API Key for {0}: '.format(args.url))
    else:
        key = os.environ.get('MISP_KEY')

    if not key:
        raise NoApiKeyError('No API key given. Can not connect to MISP this way.')

    # Check if certificate is a file, or set validation to true
    if args.ssl and os.path.isfile(args.ssl):
        ssl = args.ssl
    else:
        ssl = True

    # Create misp session and do things
    with Yaraexporter(url=args.url, key=key, ssl=ssl, debug=args.debug) as con:
        if args.debug:
            print('[DEBUG] Connected to {}.'.format(args.url))
        ruleset = con.get_rules_for_type(type_attribute=args.attribute)
        if args.file:
            if args.debug:
                print('[DEBUG] Writing rules to file {}.'.format(args.file))
            with io.open(args.file, mode='w') as file:
                file.write(ruleset)
        else:
            print(ruleset)

    # Compiling the rule
    if args.compileyara and args.file:
        cfile = args.file.split('.')[0]
        if args.debug:
            print('[DEBUG] Compiling rules to {}.'.format(cfile))
        rules = yara.compile(args.file)
        rules.save('{}.yas'.format(cfile))


if __name__ == '__main__':
    try:
        run()
    except YaraexporterError as e:
        print(e.message)
