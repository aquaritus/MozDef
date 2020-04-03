from functools import reduce
import typing as types

from mozdef_util.query_models import SearchQuery, TermMatch
from mozdef_util.elasticsearch_client import ElasticsearchClient as ESClient

from mozdef_analysis import DEFAULT_EVENTS_INDICES, SearchWindow


# Commands that may be executed by a threat actor performing
# first-time reconnaisance.
RECON = [
    ['id'],
    ['w'],
    ['whoami'],
    ['ip'],
    ['ifconfig'],
    ['hostname'],
]

# Commands that may be executed by a threat actor attempting to capture
# network traffic.
TRAFFIC_CAPTURE = [
    ['tcpdump', '-w'],
    ['tcpdump', '>'],
    ['tshark'],
    ['ip', 'promisc', 'on'],
]

# Commands that may be run by a threat actor downloading content from
# the Internet.
DOWNLOAD = [
    ['curl'],
    ['wget'],
]

# Commands that may be run by a threat actor installing executables in trusted
# locations on a host.
MALICIOUS_INSTALL = [
    ['cp', '/sbin'],
    ['cp', '/usr'],
    ['cp', '/bin'],
    ['cp', '/lib'],
]


ALL_COMMANDS = [
    RECON,
    TRAFFIC_CAPTURE,
    DOWNLOAD,
    MALICIOUS_INSTALL,
]


def _retrieve_audit_events(
    es: ESClient,
    window: SearchWindow,
    indices: types.List[str]=DEFAULT_EVENTS_INDICES,
    original_user: types.Optional[str]=None,
    host_name: types.Optional[str]=None,
) -> types.List[dict]:
    '''
    '''

    query = SearchQuery(**window.to_dict())

    query.add_must(TermMatch('tags', 'audit'))

    query.add_must_not(TermMatch('details.tty', '(none)'))

    if original_user is not None:
        query.add_must(TermMatch('details.originaluser', original_user))

    if host_name is not None:
        query.add_must(TermMatch('hostname', host_name))

    results = query.execute(es, indices)

    hits = [
        hit.get('_source', {})
        for hit in results.get('hits', [])
    ]

    return hits


def _was_executed(command: types.List[str], event: dict) -> bool:
    '''
    '''

    cmd_parts = event.get('details', {}).get('command', '').split(' ')

    same_cmd = command[0] == cmd_parts[0]

    args_present = all([
        arg in cmd_parts[1:]
        for arg in command[1:]
    ])

    return same_cmd and args_present


def search_dangerous_activity(
    es: ESClient,
    window: SearchWindow,
    indices: types.List[str]=DEFAULT_EVENTS_INDICES,
    original_user: types.Optional[str]=None,
    host_name: types.Optional[str]=None,
    dangerous_commands: types.List[types.List[str]]=ALL_COMMANDS,
) -> types.List[dict]:
    '''
    '''

    evts = _retrieve_audit_events(es, window, indices, original_user, host_name)

    all_cmds = reduce(lambda a, b: a + b, dangerous_commands, [])

    return [
        evt
        for evt in evts
        if any([_was_executed(cmd, evt) for cmd in all_cmds])
    ]
