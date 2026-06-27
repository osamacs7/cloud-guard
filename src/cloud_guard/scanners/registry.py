from cloud_guard.scanners.base import BaseScanner

scanner_registry: dict[str, type[BaseScanner]] = {}


def register_scanner(provider: str):
    def decorator(cls: type[BaseScanner]):
        scanner_registry[provider] = cls
        return cls
    return decorator
