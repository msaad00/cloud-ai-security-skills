"""Tests for CIS AWS Foundations Benchmark v3.0 checks.

Uses moto to mock AWS services — no real AWS credentials needed.
"""

from __future__ import annotations

import os
import sys

import boto3
from moto import mock_aws

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checks import (
    Finding,
    check_1_1_root_mfa,
    check_1_2_user_mfa,
    check_1_5_password_policy,
    check_1_6_no_root_keys,
    check_1_7_no_inline_policies,
    check_2_1_s3_encryption,
    check_2_3_s3_public_access,
    check_2_4_s3_versioning,
    check_4_1_no_unrestricted_ssh,
    check_4_2_no_unrestricted_rdp,
    check_4_3_vpc_flow_logs,
)


@mock_aws
class TestIAMChecks:
    def test_1_1_root_mfa_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_1_root_mfa(iam)
        assert isinstance(f, Finding)
        assert f.control_id == "1.1"
        assert f.severity == "CRITICAL"
        assert f.nist_csf == "PR.AC-1"

    def test_1_2_no_users_passes(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_2_user_mfa(iam)
        assert f.status == "PASS"

    def test_1_5_password_policy(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
        )
        f = check_1_5_password_policy(iam)
        assert f.control_id == "1.5"
        assert f.status == "PASS"

    def test_1_6_no_root_keys(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_6_no_root_keys(iam)
        assert f.control_id == "1.6"
        assert f.severity == "CRITICAL"

    def test_1_7_no_inline_policies_pass(self):
        iam = boto3.client("iam", region_name="us-east-1")
        f = check_1_7_no_inline_policies(iam)
        assert f.status == "PASS"

    def test_1_7_inline_policy_fails(self):
        iam = boto3.client("iam", region_name="us-east-1")
        iam.create_user(UserName="testuser")
        iam.put_user_policy(
            UserName="testuser",
            PolicyName="inline-policy",
            PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}',
        )
        f = check_1_7_no_inline_policies(iam)
        assert f.status == "FAIL"
        assert "testuser" in f.resources


@mock_aws
class TestStorageChecks:
    def test_2_1_s3_encryption(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        f = check_2_1_s3_encryption(s3)
        assert f.control_id == "2.1"

    def test_2_3_public_access_blocked(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        s3.put_public_access_block(
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        f = check_2_3_s3_public_access(s3)
        assert f.control_id == "2.3"

    def test_2_4_versioning(self):
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="test-bucket")
        f = check_2_4_s3_versioning(s3)
        assert f.control_id == "2.4"


@mock_aws
class TestNetworkChecks:
    def test_4_1_ssh_open_fails(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        sg = ec2.create_security_group(GroupName="open-ssh", Description="test", VpcId=vpc["Vpc"]["VpcId"])
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        f = check_4_1_no_unrestricted_ssh(ec2)
        assert f.status == "FAIL"

    def test_4_2_rdp_closed_passes(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        f = check_4_2_no_unrestricted_rdp(ec2)
        # Default SGs don't have RDP open
        assert f.control_id == "4.2"

    def test_4_3_vpc_flow_logs(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        f = check_4_3_vpc_flow_logs(ec2)
        assert f.control_id == "4.3"


@mock_aws
class TestFindingCompliance:
    def test_all_checks_have_nist_mapping(self):
        iam = boto3.client("iam", region_name="us-east-1")
        checks = [
            check_1_1_root_mfa(iam),
            check_1_2_user_mfa(iam),
            check_1_5_password_policy(iam),
            check_1_6_no_root_keys(iam),
            check_1_7_no_inline_policies(iam),
        ]
        for f in checks:
            assert f.nist_csf, f"Check {f.control_id} missing NIST CSF mapping"
            assert f.iso_27001, f"Check {f.control_id} missing ISO 27001 mapping"
