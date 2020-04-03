import typing as types


DEFAULT_EVENTS_INDICES = [
    'events-*',
]


class SearchWindow(types.NamedTuple):
    seconds: types.Optional[int] = None
    minutes: types.Optional[int] = None
    hours: types.Optional[int] = None
    days: types.Optional[int] = None

    def to_dict(self):
        return {
            k: v
            for k, v in dict(self._asdict())
            if v is not None
        }
