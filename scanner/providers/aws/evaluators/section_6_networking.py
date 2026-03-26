"""CIS AWS v6.0 Section 6: Networking — 7 controls."""

import logging
from .base import AWSClientCache, EvalConfig, make_result, make_manual_result

logger = logging.getLogger(__name__)
FW = ["CIS-AWS-6.0"]

ADMIN_PORTS = [22, 3389]  # SSH, RDP


# 6.1.1 — EBS volume encryption enabled in all regions
def evaluate_cis_6_1_1(c, cfg):
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            resp = ec2.get_ebs_encryption_by_default()
            enabled = resp.get("EbsEncryptionByDefault", False)
            results.append(make_result(cis_id="6.1.1", check_id="aws_cis_6_1_1",
                title="Ensure EBS volume encryption is enabled in all regions",
                service="networking", severity="high", region=region,
                status="PASS" if enabled else "FAIL",
                resource_id=f"ebs-default-encryption:{region}",
                status_extended=f"EBS default encryption in {region}: {enabled}",
                remediation=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                compliance_frameworks=FW))
        except Exception:
            results.append(make_result(cis_id="6.1.1", check_id="aws_cis_6_1_1",
                title="Ensure EBS volume encryption is enabled in all regions",
                service="networking", severity="high", region=region, status="FAIL",
                resource_id=f"ebs-default-encryption:{region}",
                status_extended=f"Could not check EBS default encryption in {region}.",
                compliance_frameworks=FW))
    return results


# 6.1.2 — CIFS access restricted (port 445)
def evaluate_cis_6_1_2(c, cfg):
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                sgid = sg["GroupId"]
                sgname = sg.get("GroupName", "")
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 0)
                    if from_port is None or to_port is None:
                        continue
                    if not (from_port <= 445 <= to_port):
                        continue
                    for cidr in perm.get("IpRanges", []):
                        if cidr.get("CidrIp") in ("0.0.0.0/0",):
                            results.append(make_result(cis_id="6.1.2", check_id="aws_cis_6_1_2",
                                title="Ensure CIFS access is restricted to trusted networks",
                                service="networking", severity="critical", region=region,
                                status="FAIL", resource_id=sgid, resource_name=sgname,
                                status_extended=f"SG {sgname} ({sgid}) allows 0.0.0.0/0 on CIFS (445)",
                                remediation="Restrict port 445 access to specific trusted CIDRs.",
                                compliance_frameworks=FW))
                    for cidr6 in perm.get("Ipv6Ranges", []):
                        if cidr6.get("CidrIpv6") == "::/0":
                            results.append(make_result(cis_id="6.1.2", check_id="aws_cis_6_1_2",
                                title="Ensure CIFS access is restricted to trusted networks",
                                service="networking", severity="critical", region=region,
                                status="FAIL", resource_id=sgid, resource_name=sgname,
                                status_extended=f"SG {sgname} ({sgid}) allows ::/0 on CIFS (445)",
                                remediation="Restrict port 445 IPv6 access to trusted CIDRs.",
                                compliance_frameworks=FW))
        except Exception:
            pass
    return results


def _check_sg_admin_ports(c, cfg, cis_id, check_id, title, cidr_field, cidr_value, ip_version):
    """Generic check: no SGs allow cidr_value on admin ports."""
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
            for sg in sgs:
                sgid, sgname = sg["GroupId"], sg.get("GroupName", "")
                for perm in sg.get("IpPermissions", []):
                    proto = perm.get("IpProtocol", "")
                    if proto not in ("tcp", "6", "-1"):
                        continue
                    from_p = perm.get("FromPort", 0) or 0
                    to_p = perm.get("ToPort", 65535) or 65535
                    for port in ADMIN_PORTS:
                        if from_p <= port <= to_p:
                            for cidr in perm.get(cidr_field, []):
                                val = cidr.get("CidrIp" if "Ip" in cidr_field else "CidrIpv6", "")
                                if val == cidr_value:
                                    results.append(make_result(
                                        cis_id=cis_id, check_id=check_id, title=title,
                                        service="networking", severity="critical", region=region,
                                        status="FAIL", resource_id=sgid, resource_name=sgname,
                                        status_extended=f"SG {sgname} ({sgid}) allows {cidr_value} on port {port}",
                                        remediation=f"Restrict {ip_version} access on port {port} to specific CIDRs.",
                                        compliance_frameworks=FW))
        except Exception:
            pass
    return results


# 6.2 — No NACLs allow 0.0.0.0/0 to admin ports
def evaluate_cis_6_2(c, cfg):
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            nacls = ec2.describe_network_acls()["NetworkAcls"]
            for nacl in nacls:
                nid = nacl["NetworkAclId"]
                for entry in nacl.get("Entries", []):
                    if entry.get("Egress", False):
                        continue
                    if entry.get("RuleAction") != "allow":
                        continue
                    cidr = entry.get("CidrBlock", "")
                    if cidr != "0.0.0.0/0":
                        continue
                    proto = str(entry.get("Protocol", "-1"))
                    if proto == "-1":  # All traffic
                        results.append(make_result(cis_id="6.2", check_id="aws_cis_6_2",
                            title="Ensure no NACLs allow ingress from 0.0.0.0/0 to remote server admin ports",
                            service="networking", severity="critical", region=region,
                            status="FAIL", resource_id=nid,
                            status_extended=f"NACL {nid}: allows ALL inbound from 0.0.0.0/0",
                            remediation="Restrict NACL to deny 0.0.0.0/0 on admin ports.",
                            compliance_frameworks=FW))
                    elif proto == "6":  # TCP
                        port_range = entry.get("PortRange", {})
                        from_p = port_range.get("From", 0)
                        to_p = port_range.get("To", 65535)
                        for port in ADMIN_PORTS:
                            if from_p <= port <= to_p:
                                results.append(make_result(cis_id="6.2", check_id="aws_cis_6_2",
                                    title="Ensure no NACLs allow ingress from 0.0.0.0/0 to remote server admin ports",
                                    service="networking", severity="critical", region=region,
                                    status="FAIL", resource_id=nid,
                                    status_extended=f"NACL {nid}: allows 0.0.0.0/0 on port {port}",
                                    remediation=f"Restrict NACL inbound rule for port {port}.",
                                    compliance_frameworks=FW))
        except Exception:
            pass
    return results


# 6.3 — No SGs allow 0.0.0.0/0 to admin ports (IPv4)
def evaluate_cis_6_3(c, cfg):
    return _check_sg_admin_ports(c, cfg, "6.3", "aws_cis_6_3",
        "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server admin ports",
        "IpRanges", "0.0.0.0/0", "IPv4")


# 6.4 — No SGs allow ::/0 to admin ports (IPv6)
def evaluate_cis_6_4(c, cfg):
    return _check_sg_admin_ports(c, cfg, "6.4", "aws_cis_6_4",
        "Ensure no security groups allow ingress from ::/0 to remote server admin ports",
        "Ipv6Ranges", "::/0", "IPv6")


# 6.5 — Default SG restricts all traffic
def evaluate_cis_6_5(c, cfg):
    results = []
    for region in c.regions:
        ec2 = c.client("ec2", region)
        try:
            sgs = ec2.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )["SecurityGroups"]
            for sg in sgs:
                has_ingress = bool(sg.get("IpPermissions", []))
                has_egress = bool(sg.get("IpPermissionsEgress", []))
                unrestricted = has_ingress or has_egress
                results.append(make_result(cis_id="6.5", check_id="aws_cis_6_5",
                    title="Ensure the default security group of every VPC restricts all traffic",
                    service="networking", severity="high", region=region,
                    status="FAIL" if unrestricted else "PASS",
                    resource_id=sg["GroupId"],
                    status_extended=f"Default SG {sg['GroupId']}: ingress rules={has_ingress}, egress rules={has_egress}",
                    remediation="Remove all inbound and outbound rules from the default SG.",
                    compliance_frameworks=FW))
        except Exception:
            pass
    return results


# 6.6 — VPC peering routing least access (MANUAL)
def evaluate_cis_6_6(c, cfg):
    return [make_manual_result("6.6", "aws_cis_6_6",
        "Ensure routing tables for VPC peering are least access",
        "networking", "high", cfg.account_id,
        "Requires reviewing VPC peering route tables for overly permissive CIDR entries.")]
