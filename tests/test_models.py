"""Tests for D-ARCA database models — CRUD operations via async SQLAlchemy."""
import uuid
import json
import pytest
from datetime import datetime

from api.models.user import User
from api.models.organization import Organization
from api.models.provider import Provider
from api.models.scan import Scan
from api.models.finding import Finding
from api.models.api_key import ApiKey
from api.models.attack_path import AttackPath
from api.models.saas_connection import SaaSConnection
from api.models.custom_framework import CustomFramework, CustomFrameworkCheck, CustomControl

from sqlalchemy import select


# ── User model ───────────────────────────────────────────────────


class TestUserModel:
    async def test_create_user(self, db_session):
        user = User(
            email="test@example.com",
            hashed_password="hashed123",
            name="Test User",
            role="admin",
        )
        db_session.add(user)
        await db_session.commit()

        result = await db_session.execute(select(User).where(User.email == "test@example.com"))
        saved = result.scalar_one()
        assert saved.name == "Test User"
        assert saved.role == "admin"
        assert saved.is_active is True
        assert saved.id is not None

    async def test_user_defaults(self, db_session):
        user = User(email="defaults@test.com", hashed_password="x", name="Default")
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)

        assert user.role == "viewer"
        assert user.org_role == "member"
        assert user.is_active is True
        assert isinstance(user.created_at, datetime)

    async def test_user_unique_email(self, db_session):
        user1 = User(email="dup@test.com", hashed_password="x", name="A")
        db_session.add(user1)
        await db_session.commit()

        user2 = User(email="dup@test.com", hashed_password="y", name="B")
        db_session.add(user2)
        with pytest.raises(Exception):
            await db_session.commit()
        await db_session.rollback()


# ── Organization model ───────────────────────────────────────────


class TestOrganizationModel:
    async def test_create_organization(self, db_session):
        org = Organization(name="Acme Corp", slug="acme-corp", plan="pro")
        db_session.add(org)
        await db_session.commit()

        result = await db_session.execute(select(Organization).where(Organization.slug == "acme-corp"))
        saved = result.scalar_one()
        assert saved.name == "Acme Corp"
        assert saved.plan == "pro"
        assert saved.is_active is True

    async def test_organization_defaults(self, db_session):
        org = Organization(name="Free Org", slug="free-org")
        db_session.add(org)
        await db_session.commit()
        await db_session.refresh(org)
        assert org.plan == "free"


# ── Provider model ───────────────────────────────────────────────


class TestProviderModel:
    async def test_create_provider(self, db_session):
        user = User(email="prov@test.com", hashed_password="x", name="Prov User")
        db_session.add(user)
        await db_session.commit()

        provider = Provider(
            user_id=user.id,
            provider_type="aws",
            alias="My AWS Account",
            account_id="123456789012",
            region="us-east-1",
        )
        db_session.add(provider)
        await db_session.commit()

        result = await db_session.execute(select(Provider).where(Provider.user_id == user.id))
        saved = result.scalar_one()
        assert saved.provider_type == "aws"
        assert saved.alias == "My AWS Account"
        assert saved.status == "connected"
        assert saved.account_type == "single"
        assert saved.is_management_account is False


# ── Scan model ───────────────────────────────────────────────────


class TestScanModel:
    async def test_create_scan(self, db_session):
        user = User(email="scan@test.com", hashed_password="x", name="Scan User")
        db_session.add(user)
        await db_session.commit()

        provider = Provider(user_id=user.id, provider_type="azure", alias="Azure Sub")
        db_session.add(provider)
        await db_session.commit()

        scan = Scan(
            user_id=user.id,
            provider_id=provider.id,
            scan_type="cloud",
            total_checks=100,
            passed_checks=80,
            failed_checks=20,
        )
        db_session.add(scan)
        await db_session.commit()

        result = await db_session.execute(select(Scan).where(Scan.user_id == user.id))
        saved = result.scalar_one()
        assert saved.scan_type == "cloud"
        assert saved.status == "pending"
        assert saved.progress == 0.0
        assert saved.total_checks == 100

    async def test_scan_status_update(self, db_session):
        user = User(email="scanup@test.com", hashed_password="x", name="U")
        db_session.add(user)
        await db_session.commit()

        scan = Scan(user_id=user.id, scan_type="saas")
        db_session.add(scan)
        await db_session.commit()

        scan.status = "completed"
        scan.progress = 100.0
        scan.completed_at = datetime.utcnow()
        await db_session.commit()
        await db_session.refresh(scan)

        assert scan.status == "completed"
        assert scan.progress == 100.0
        assert scan.completed_at is not None


# ── Finding model ────────────────────────────────────────────────


class TestFindingModel:
    async def _setup(self, db_session):
        user = User(email="find@test.com", hashed_password="x", name="F")
        db_session.add(user)
        await db_session.commit()

        provider = Provider(user_id=user.id, provider_type="aws", alias="AWS")
        db_session.add(provider)
        await db_session.commit()

        scan = Scan(user_id=user.id, provider_id=provider.id, scan_type="cloud")
        db_session.add(scan)
        await db_session.commit()
        return user, provider, scan

    async def test_create_finding(self, db_session):
        user, provider, scan = await self._setup(db_session)

        finding = Finding(
            scan_id=scan.id,
            provider_id=provider.id,
            check_id="aws_s3_bucket_public",
            check_title="S3 Bucket Public Access",
            service="S3",
            severity="high",
            status="FAIL",
            region="us-east-1",
            resource_id="arn:aws:s3:::my-bucket",
            resource_name="my-bucket",
            status_extended="Bucket my-bucket allows public access",
            remediation="Block public access on the S3 bucket",
        )
        db_session.add(finding)
        await db_session.commit()

        result = await db_session.execute(
            select(Finding).where(Finding.scan_id == scan.id)
        )
        saved = result.scalar_one()
        assert saved.severity == "high"
        assert saved.status == "FAIL"
        assert saved.check_id == "aws_s3_bucket_public"

    async def test_finding_with_compliance_and_mitre(self, db_session):
        user, provider, scan = await self._setup(db_session)

        frameworks = json.dumps(["CIS-AWS-6.0", "PCI-DSS-4.0"])
        mitre = json.dumps(["T1530", "T1078"])

        finding = Finding(
            scan_id=scan.id,
            provider_id=provider.id,
            check_id="test_check",
            check_title="Test",
            service="S3",
            severity="medium",
            status="PASS",
            compliance_frameworks=frameworks,
            mitre_techniques=mitre,
        )
        db_session.add(finding)
        await db_session.commit()

        result = await db_session.execute(select(Finding).where(Finding.check_id == "test_check"))
        saved = result.scalar_one()
        parsed_fw = json.loads(saved.compliance_frameworks)
        assert "CIS-AWS-6.0" in parsed_fw
        parsed_mitre = json.loads(saved.mitre_techniques)
        assert "T1530" in parsed_mitre


# ── ApiKey model ─────────────────────────────────────────────────


class TestApiKeyModel:
    async def test_generate_key(self):
        key = ApiKey.generate_key()
        assert key.startswith("darca_")
        assert len(key) == 54  # "darca_" (6) + 48 hex chars

    async def test_create_api_key(self, db_session):
        user = User(email="apikey@test.com", hashed_password="x", name="Key User")
        db_session.add(user)
        await db_session.commit()

        import hashlib
        raw_key = ApiKey.generate_key()
        api_key = ApiKey(
            user_id=user.id,
            name="CI/CD Key",
            key_prefix=raw_key[:12],
            key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
        )
        db_session.add(api_key)
        await db_session.commit()

        result = await db_session.execute(select(ApiKey).where(ApiKey.user_id == user.id))
        saved = result.scalar_one()
        assert saved.name == "CI/CD Key"
        assert saved.active is True
        assert saved.key_prefix == raw_key[:12]


# ── AttackPath model ─────────────────────────────────────────────


class TestAttackPathModel:
    async def test_create_attack_path(self, db_session):
        user = User(email="ap@test.com", hashed_password="x", name="AP")
        db_session.add(user)
        await db_session.commit()

        ap = AttackPath(
            user_id=user.id,
            title="Privilege Escalation via IAM",
            description="An attacker can escalate privileges through over-permissive IAM",
            severity="critical",
            risk_score=9.2,
            category="Privilege Escalation",
            entry_point="IAM User with PutRolePolicy",
            target="Admin Role",
            node_count=3,
            edge_count=2,
            techniques=json.dumps(["T1078", "T1098"]),
            affected_resources=json.dumps(["arn:aws:iam::123:role/admin"]),
            remediation=json.dumps(["Remove PutRolePolicy permission"]),
            graph_data=json.dumps({"nodes": [], "edges": []}),
        )
        db_session.add(ap)
        await db_session.commit()

        result = await db_session.execute(select(AttackPath).where(AttackPath.user_id == user.id))
        saved = result.scalar_one()
        assert saved.severity == "critical"
        assert saved.risk_score == 9.2
        assert json.loads(saved.techniques) == ["T1078", "T1098"]


# ── SaaSConnection model ────────────────────────────────────────


class TestSaaSConnectionModel:
    async def test_create_saas_connection(self, db_session):
        user = User(email="saas@test.com", hashed_password="x", name="SaaS User")
        db_session.add(user)
        await db_session.commit()

        conn = SaaSConnection(
            user_id=user.id,
            provider_type="servicenow",
            alias="ServiceNow Prod",
            credentials_encrypted="encrypted_base64_data",
        )
        db_session.add(conn)
        await db_session.commit()

        result = await db_session.execute(select(SaaSConnection).where(SaaSConnection.user_id == user.id))
        saved = result.scalar_one()
        assert saved.provider_type == "servicenow"
        assert saved.status == "connected"
        assert saved.is_active is True


# ── CustomFramework model ───────────────────────────────────────


class TestCustomFrameworkModel:
    async def test_create_framework_with_checks_and_controls(self, db_session):
        user = User(email="cf@test.com", hashed_password="x", name="CF User")
        db_session.add(user)
        await db_session.commit()

        fw = CustomFramework(
            user_id=user.id,
            name="My Security Framework",
            description="Custom framework for internal compliance",
            version="1.0",
            providers=json.dumps(["aws", "azure"]),
        )
        db_session.add(fw)
        await db_session.commit()

        # Add a registry check reference
        check = CustomFrameworkCheck(
            framework_id=fw.id,
            registry_check_id="cis_aws_2_1_1",
            display_order=1,
        )
        db_session.add(check)

        # Add a custom control
        ctrl = CustomControl(
            framework_id=fw.id,
            check_id="CUSTOM-001",
            title="Custom Encryption Check",
            description="Ensure all data at rest is encrypted",
            severity="high",
            provider="aws",
            service="S3",
            category="Encryption",
            assessment_type="manual",
            remediation="Enable SSE-S3 on all buckets",
            tags=json.dumps(["encryption", "custom"]),
        )
        db_session.add(ctrl)
        await db_session.commit()

        result = await db_session.execute(
            select(CustomFramework).where(CustomFramework.user_id == user.id)
        )
        saved = result.scalar_one()
        assert saved.name == "My Security Framework"
        assert json.loads(saved.providers) == ["aws", "azure"]

        checks_result = await db_session.execute(
            select(CustomFrameworkCheck).where(CustomFrameworkCheck.framework_id == fw.id)
        )
        checks = checks_result.scalars().all()
        assert len(checks) == 1
        assert checks[0].registry_check_id == "cis_aws_2_1_1"

        ctrls_result = await db_session.execute(
            select(CustomControl).where(CustomControl.framework_id == fw.id)
        )
        ctrls = ctrls_result.scalars().all()
        assert len(ctrls) == 1
        assert ctrls[0].check_id == "CUSTOM-001"
        assert ctrls[0].severity == "high"
