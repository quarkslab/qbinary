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

"""Custom Abstract Base Classes (ABC)

Fast implementation of meta classes to have abstract attributes"""

from __future__ import annotations
from abc import ABCMeta


class ABCMetaAttributes(ABCMeta):
    __cached_cls: set[type] = set()  # Caching classes to avoid overhead

    def __call__(cls, *args, **kwargs):
        instance = super().__call__(*args, **kwargs)
        if cls not in ABCMetaAttributes.__cached_cls:
            # Use a set internally to remove duplicates
            abstract_attributes = ", ".join(
                {
                    name
                    for pcls in cls.mro()
                    for name in getattr(pcls, "__slots__", "")
                    # Ignore class specific attributes (starting with __)
                    if not (name.startswith("__") or hasattr(instance, name))
                }
            )
            if abstract_attributes:
                raise NotImplementedError(
                    f"Can't instantiate abstract class {cls.__name__} "
                    f"without the following attributes {abstract_attributes}"
                )
            ABCMetaAttributes.__cached_cls.add(cls)
        return instance
