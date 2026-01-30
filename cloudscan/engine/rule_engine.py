"""
Rule engine - Orchestrates rule evaluation.

Loads all rules and evaluates them against the scan context.
"""

import logging
from typing import List, Dict, Type
from pathlib import Path
import importlib
import inspect

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


logger = logging.getLogger(__name__)


class RuleEngine:
    """Orchestrates security rule evaluation."""

    def __init__(self):
        """Initialize rule engine."""
        self.rules: List[BaseRule] = []
        self.logger = logging.getLogger("cloudscan.engine")

    def load_rules(self, rules_dir: str = None) -> None:
        """
        Dynamically load all rule classes from the rules directory.

        Args:
            rules_dir: Path to rules directory (default: cloudscan/rules)
        """
        if rules_dir is None:
            rules_dir = str(Path(__file__).parent.parent / "rules")

        self.logger.info(f"Loading rules from {rules_dir}")

        rules_path = Path(rules_dir)
        rule_files = sorted(rules_path.glob("*.py"))

        for rule_file in rule_files:
            # Skip base.py and __init__.py
            if rule_file.name in ("base.py", "__init__.py"):
                continue

            self._load_rules_from_file(rule_file)

        self.logger.info(f"Loaded {len(self.rules)} rules")

    def _load_rules_from_file(self, rule_file: Path) -> None:
        """
        Load rule classes from a Python file.

        Args:
            rule_file: Path to rule file
        """
        try:
            # Import the module
            module_name = f"cloudscan.rules.{rule_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, rule_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find rule classes
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and
                        issubclass(obj, BaseRule) and
                        obj is not BaseRule):
                        rule_instance = obj()
                        self.rules.append(rule_instance)
                        self.logger.debug(f"Loaded rule: {rule_instance.id}")

        except Exception as e:
            self.logger.error(f"Error loading rules from {rule_file}: {e}")

    def evaluate(self, context: ScanContext) -> List[Finding]:
        """
        Evaluate all rules against the scan context.

        Args:
            context: ScanContext with collected AWS data

        Returns:
            List of all findings
        """
        self.logger.info(f"Evaluating {len(self.rules)} rules")

        all_findings = []
        for rule in self.rules:
            try:
                findings = rule.evaluate(context)
                all_findings.extend(findings)
                self.logger.debug(
                    f"Rule {rule.id} found {len(findings)} issues"
                )

            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.id}: {e}")

        # Sort by severity (CRITICAL -> INFO)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        all_findings.sort(
            key=lambda f: severity_order.get(f.severity, 99)
        )

        self.logger.info(f"Evaluation complete: {len(all_findings)} findings")
        return all_findings

    def get_rules_by_service(self, service: str) -> List[BaseRule]:
        """
        Get all rules for a specific service.

        Args:
            service: Service name (iam, s3, ec2, rds)

        Returns:
            List of rules for that service
        """
        return [rule for rule in self.rules if rule.service == service]

    def get_rules_by_severity(self, severity: Severity) -> List[BaseRule]:
        """
        Get all rules with a specific severity.

        Args:
            severity: Severity level

        Returns:
            List of rules with that severity
        """
        return [rule for rule in self.rules if rule.severity == severity]

    def __repr__(self) -> str:
        return f"<RuleEngine {len(self.rules)} rules>"
