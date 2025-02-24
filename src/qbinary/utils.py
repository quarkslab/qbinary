# Copyright 2025 Quarkslab
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Collection of utilities

Collection of utilities used internally"""

from __future__ import annotations
import logging, functools
from types import GenericAlias

_NOT_FOUND = object()


class cached_property:
    """
    Custom implementation of cached_property that works with __slots__.
    It uses the entry _cached_properties that needs to be defined in __slots__.
    """

    def __init__(self, func):
        self.attrname = None
        functools.update_wrapper(self, func)

    def __set_name__(self, owner, name):
        if self.attrname is None:
            self.attrname = name
        elif name != self.attrname:
            raise TypeError(
                "Cannot assign the same cached_property to two different names "
                f"({self.attrname!r} and {name!r})."
            )

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        if self.attrname is None:
            raise TypeError(
                "Cannot use cached_property instance without calling __set_name__ on it."
            )
        try:
            if not hasattr(instance, "_cached_properties"):
                instance._cached_properties = {}
            cache = getattr(instance, "_cached_properties")
        except AttributeError:
            msg = (
                f"Cannot find the attribute '_cached_properties' on {type(instance).__name__!r}. "
                "Set it in the __slots__ property"
            )
            raise TypeError(msg) from None
        val = cache.get(self.attrname, _NOT_FOUND)
        if val is _NOT_FOUND:
            val = self.__wrapped__(instance)
            cache[self.attrname] = val
        return val

    __class_getitem__ = classmethod(GenericAlias)  # type: ignore[var-annotated]


@functools.cache
def log_once(level: int, message: str) -> None:
    """
    Log a message with the corresponding level only once.

    :param level: The severity level of the logging
    :param message: The message to log
    """

    logging.log(level, message)
