"""Tests for SG-001: security group open to 0.0.0.0/0 on dangerous ports."""

from cloudscan.rules.sg_open_world import SecurityGroupOpenRule
from tests.conftest import make_context, make_inbound_rule, make_security_group


def evaluate(sg, ec2_service):
    ctx = make_context(ec2=ec2_service(security_groups=[sg]))
    return SecurityGroupOpenRule().evaluate(ctx)


class TestSecurityGroupOpenRule:
    def test_open_ssh_flagged(self, ec2_service):
        sg = make_security_group(sg_id="sg-ssh", inbound_rules=[
            make_inbound_rule(protocol="tcp", from_port=22, to_port=22, cidr="0.0.0.0/0")
        ])
        findings = evaluate(sg, ec2_service)
        assert len(findings) == 1
        assert findings[0].rule_id == "SG-001"
        assert findings[0].severity.value == "HIGH"
        assert findings[0].resource_id == "sg-ssh"

    def test_open_rdp_flagged(self, ec2_service):
        sg = make_security_group(sg_id="sg-rdp", inbound_rules=[
            make_inbound_rule(protocol="tcp", from_port=3389, to_port=3389, cidr="0.0.0.0/0")
        ])
        findings = evaluate(sg, ec2_service)
        assert len(findings) == 1

    def test_all_protocols_open_flagged(self, ec2_service):
        sg = make_security_group(sg_id="sg-any", inbound_rules=[
            make_inbound_rule(protocol="-1", from_port=None, to_port=None, cidr="0.0.0.0/0")
        ])
        findings = evaluate(sg, ec2_service)
        assert len(findings) == 1

    def test_open_http_not_flagged(self, ec2_service):
        """Port 80 isn't in the dangerous-ports list, so it should not fire."""
        sg = make_security_group(sg_id="sg-http", inbound_rules=[
            make_inbound_rule(protocol="tcp", from_port=80, to_port=80, cidr="0.0.0.0/0")
        ])
        findings = evaluate(sg, ec2_service)
        assert findings == []

    def test_restricted_cidr_not_flagged(self, ec2_service):
        sg = make_security_group(sg_id="sg-restricted", inbound_rules=[
            make_inbound_rule(protocol="tcp", from_port=22, to_port=22, cidr="10.0.0.0/8")
        ])
        findings = evaluate(sg, ec2_service)
        assert findings == []

    def test_no_rules_not_flagged(self, ec2_service):
        sg = make_security_group(sg_id="sg-empty", inbound_rules=[])
        findings = evaluate(sg, ec2_service)
        assert findings == []

    def test_port_range_including_dangerous_port_flagged(self, ec2_service):
        sg = make_security_group(sg_id="sg-range", inbound_rules=[
            make_inbound_rule(protocol="tcp", from_port=20, to_port=25, cidr="0.0.0.0/0")
        ])
        findings = evaluate(sg, ec2_service)
        assert len(findings) == 1  # port 22 falls within 20-25
