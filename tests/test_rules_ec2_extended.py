"""Tests for the expanded EC2/VPC rules: broad non-dangerous ports, IPv6
open access, default security group, internet-exposed instances, and
IMDSv2 enforcement."""

from cloudscan.rules.ec2_imdsv2_not_enforced import IMDSv2NotEnforcedRule
from cloudscan.rules.ec2_internet_exposed_instance import InternetExposedInstanceRule
from cloudscan.rules.sg_any_port_open import SecurityGroupAnyPortOpenRule
from cloudscan.rules.sg_default_allows_traffic import DefaultSecurityGroupRule
from cloudscan.rules.sg_open_world_ipv6 import SecurityGroupOpenIPv6Rule
from tests.conftest import make_context, make_inbound_rule, make_security_group


def sg_with_rule(rule, **sg_kwargs):
    return make_security_group(inbound_rules=[rule], **sg_kwargs)


class TestSecurityGroupAnyPortOpenRule:
    def test_open_non_dangerous_port_flagged(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=8080, to_port=8080, cidr="0.0.0.0/0"))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        findings = SecurityGroupAnyPortOpenRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_ssh_port_excluded_sg001_territory(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0"))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert SecurityGroupAnyPortOpenRule().evaluate(ctx) == []

    def test_all_protocols_excluded_sg001_territory(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(protocol="-1", from_port=None, to_port=None, cidr="0.0.0.0/0"))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert SecurityGroupAnyPortOpenRule().evaluate(ctx) == []

    def test_restricted_cidr_not_flagged(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=8080, to_port=8080, cidr="10.0.0.0/8"))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert SecurityGroupAnyPortOpenRule().evaluate(ctx) == []

    def test_range_touching_dangerous_port_excluded(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=20, to_port=25, cidr="0.0.0.0/0"))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert SecurityGroupAnyPortOpenRule().evaluate(ctx) == []


class TestSecurityGroupOpenIPv6Rule:
    def _ipv6_rule(self, from_port=22, to_port=22, protocol="tcp"):
        return {
            "protocol": protocol, "from_port": from_port, "to_port": to_port,
            "direction": "inbound", "ip_ranges": [],
            "ipv6_ranges": [{"cidr": "::/0", "description": ""}],
            "user_id_group_pairs": [],
        }

    def test_open_ipv6_ssh_flagged(self, ec2_service):
        sg = sg_with_rule(self._ipv6_rule())
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        findings = SecurityGroupOpenIPv6Rule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_open_ipv6_http_not_flagged(self, ec2_service):
        sg = sg_with_rule(self._ipv6_rule(from_port=80, to_port=80))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert SecurityGroupOpenIPv6Rule().evaluate(ctx) == []

    def test_ipv4_only_rule_not_flagged_here(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0"))
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert SecurityGroupOpenIPv6Rule().evaluate(ctx) == []


class TestDefaultSecurityGroupRule:
    def test_default_sg_with_rules_flagged(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(cidr="10.0.0.0/8"), name="default")
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        findings = DefaultSecurityGroupRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "LOW"

    def test_default_sg_empty_not_flagged(self, ec2_service):
        sg = make_security_group(name="default", inbound_rules=[])
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert DefaultSecurityGroupRule().evaluate(ctx) == []

    def test_non_default_sg_with_rules_not_flagged(self, ec2_service):
        sg = sg_with_rule(make_inbound_rule(cidr="10.0.0.0/8"), name="web-tier")
        ctx = make_context(ec2=ec2_service(security_groups=[sg]))
        assert DefaultSecurityGroupRule().evaluate(ctx) == []


class TestInternetExposedInstanceRule:
    def _instance(self, public_ip="1.2.3.4", sg_ids=("sg-open",)):
        return {
            "id": "i-1", "state": "running", "type": "t3.micro",
            "vpc_id": "vpc-1", "subnet_id": "subnet-1",
            "public_ip": public_ip, "private_ip": "10.0.0.1",
            "security_groups": [{"id": sid, "name": sid} for sid in sg_ids],
            "metadata_options": {"http_tokens": "required"}, "tags": {},
        }

    def test_public_ip_with_open_sg_flagged(self, ec2_service):
        open_sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=8080, to_port=8080, cidr="0.0.0.0/0"), sg_id="sg-open")
        instance = self._instance(sg_ids=["sg-open"])
        ctx = make_context(ec2=ec2_service(security_groups=[open_sg], instances=[instance]))
        findings = InternetExposedInstanceRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_public_ip_with_restricted_sg_not_flagged(self, ec2_service):
        restricted_sg = sg_with_rule(make_inbound_rule(cidr="10.0.0.0/8"), sg_id="sg-restricted")
        instance = self._instance(sg_ids=["sg-restricted"])
        ctx = make_context(ec2=ec2_service(security_groups=[restricted_sg], instances=[instance]))
        assert InternetExposedInstanceRule().evaluate(ctx) == []

    def test_no_public_ip_not_flagged(self, ec2_service):
        open_sg = sg_with_rule(make_inbound_rule(protocol="tcp", from_port=8080, to_port=8080, cidr="0.0.0.0/0"), sg_id="sg-open")
        instance = self._instance(public_ip=None, sg_ids=["sg-open"])
        ctx = make_context(ec2=ec2_service(security_groups=[open_sg], instances=[instance]))
        assert InternetExposedInstanceRule().evaluate(ctx) == []

    def test_open_ipv6_sg_also_counts(self, ec2_service):
        open_sg = make_security_group(sg_id="sg-open6", inbound_rules=[{
            "protocol": "tcp", "from_port": 8080, "to_port": 8080, "direction": "inbound",
            "ip_ranges": [], "ipv6_ranges": [{"cidr": "::/0", "description": ""}],
            "user_id_group_pairs": [],
        }])
        instance = self._instance(sg_ids=["sg-open6"])
        ctx = make_context(ec2=ec2_service(security_groups=[open_sg], instances=[instance]))
        findings = InternetExposedInstanceRule().evaluate(ctx)
        assert len(findings) == 1


class TestIMDSv2NotEnforcedRule:
    def _instance(self, http_tokens):
        return {
            "id": "i-1", "state": "running", "type": "t3.micro",
            "vpc_id": "vpc-1", "subnet_id": "subnet-1",
            "public_ip": None, "private_ip": "10.0.0.1", "security_groups": [],
            "metadata_options": {"http_tokens": http_tokens}, "tags": {},
        }

    def test_optional_http_tokens_flagged(self, ec2_service):
        ctx = make_context(ec2=ec2_service(instances=[self._instance("optional")]))
        findings = IMDSv2NotEnforcedRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_required_http_tokens_not_flagged(self, ec2_service):
        ctx = make_context(ec2=ec2_service(instances=[self._instance("required")]))
        assert IMDSv2NotEnforcedRule().evaluate(ctx) == []

    def test_missing_metadata_options_flagged(self, ec2_service):
        instance = self._instance("optional")
        instance["metadata_options"] = {}
        ctx = make_context(ec2=ec2_service(instances=[instance]))
        findings = IMDSv2NotEnforcedRule().evaluate(ctx)
        assert len(findings) == 1
