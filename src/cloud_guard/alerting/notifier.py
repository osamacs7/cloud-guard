import json
from abc import ABC, abstractmethod
from email.message import EmailMessage

import httpx

from cloud_guard.core.config import settings
from cloud_guard.core.logging import logger
from cloud_guard.scanners.base import ScanResult


class BaseNotifier(ABC):
    @abstractmethod
    async def send(self, result: ScanResult, scan_id: str) -> None:
        ...


class SlackNotifier(BaseNotifier):
    async def send(self, result: ScanResult, scan_id: str) -> None:
        if not settings.slack_webhook_url:
            return

        color = "#dc3545" if result.critical_count > 0 else "#ffc107" if result.high_count > 0 else "#28a745"

        payload = {
            "attachments": [{
                "color": color,
                "title": f"Cloud Guard Scan Complete — {result.provider.upper()}",
                "fields": [
                    {"title": "Scan ID", "value": scan_id, "short": True},
                    {"title": "Provider", "value": result.provider, "short": True},
                    {"title": "Total Findings", "value": str(len(result.findings)), "short": True},
                    {"title": "Critical", "value": str(result.critical_count), "short": True},
                    {"title": "High", "value": str(result.high_count), "short": True},
                    {"title": "Resources Scanned", "value": str(result.resources_scanned), "short": True},
                ],
            }],
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(settings.slack_webhook_url, json=payload)
            resp.raise_for_status()
            await logger.ainfo("slack_notification_sent", scan_id=scan_id)


class PagerDutyNotifier(BaseNotifier):
    async def send(self, result: ScanResult, scan_id: str) -> None:
        if not settings.pagerduty_api_key or result.critical_count == 0:
            return

        payload = {
            "routing_key": settings.pagerduty_api_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"Cloud Guard: {result.critical_count} critical findings in {result.provider}",
                "severity": "critical",
                "source": "cloud-guard",
                "custom_details": {
                    "scan_id": scan_id,
                    "provider": result.provider,
                    "critical_count": result.critical_count,
                    "total_findings": len(result.findings),
                },
            },
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )
            resp.raise_for_status()
            await logger.ainfo("pagerduty_alert_sent", scan_id=scan_id)


class WebhookNotifier(BaseNotifier):
    def __init__(self, url: str):
        self.url = url

    async def send(self, result: ScanResult, scan_id: str) -> None:
        payload = {
            "scan_id": scan_id,
            "provider": result.provider,
            "total_findings": len(result.findings),
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "resources_scanned": result.resources_scanned,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "resource_id": f.resource_id,
                }
                for f in result.findings
            ],
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(self.url, json=payload, timeout=30)
            resp.raise_for_status()


async def notify_all(result: ScanResult, scan_id: str) -> None:
    notifiers: list[BaseNotifier] = [SlackNotifier(), PagerDutyNotifier()]

    for notifier in notifiers:
        try:
            await notifier.send(result, scan_id)
        except Exception as e:
            await logger.aerror("notification_failed", notifier=type(notifier).__name__, error=str(e))
