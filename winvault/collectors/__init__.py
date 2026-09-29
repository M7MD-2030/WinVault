"""Collector registry. Add new collectors here to include them in snapshots."""

from .base import Collector, CollectorError
from .registry import RegistryCollector
from .services import ServicesCollector
from .startup import StartupCollector
from .tasks import ScheduledTasksCollector
from .users import UsersCollector

ALL_COLLECTORS: dict[str, type[Collector]] = {
    c.name: c
    for c in (
        RegistryCollector,
        ServicesCollector,
        ScheduledTasksCollector,
        UsersCollector,
        StartupCollector,
    )
}

__all__ = ["ALL_COLLECTORS", "Collector", "CollectorError"]
