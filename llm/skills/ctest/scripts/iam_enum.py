#!/usr/bin/env python3
"""ctest IAM enumeration — discover identity, permissions, and escalation paths."""
import json
import subprocess
import sys
from datetime import datetime


ESCALATION_PATHS = [
    # (required_permissions, technique, severity)
    (["iam:CreatePolicyVersion"], "Create admin policy version", "critical"),
    (["iam:AttachUserPolicy"], "Attach AdministratorAccess to self", "critical"),
    (["iam:AttachRolePolicy"], "Attach admin policy to assumable role", "critical"),
    (["iam:PutUserPolicy"], "Add inline admin policy to self", "critical"),
    (["iam:CreateAccessKey"], "Create access key for any user", "high"),
    (["iam:CreateLoginProfile"], "Create console password for any user", "high"),
    (["iam:UpdateLoginProfile"], "Reset any user's console password", "high"),
    (["iam:UpdateAssumeRolePolicy"], "Modify role trust policy", "high"),
    (["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Lambda privesc via PassRole", "critical"),
    (["iam:PassRole", "ec2:RunInstances"], "EC2 privesc via instance profile", "critical"),
    (["iam:PassRole", "cloudformation:CreateStack"], "CloudFormation privesc", "critical"),
    (["lambda:UpdateFunctionCode"], "Hijack existing Lambda role", "high"),
    (["ssm:SendCommand"], "Execute on managed instances", "high"),
    (["sts:AssumeRole"], "Cross-account pivot", "high"),
    (["s3:GetBucketPolicy", "s3:PutBucketPolicy"], "S3 bucket policy manipulation", "medium"),
    (["ec2:ModifyInstanceAttribute"], "Modify instance userdata for code exec", "high"),
    (["iam:PassRole", "glue:CreateJob"], "Glue job privesc", "high"),
    (["iam:PassRole", "ecs:RunTask"], "ECS task privesc", "high"),
]


def run_aws(cmd, quiet=False):
    """Run AWS CLI command, return parsed JSON or None on error."""
    try:
        result = subprocess.run(
            ["aws"] + cmd.split(),
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            if not quiet:
                print(f"  ✗ aws {cmd}: {result.stderr.strip()[:100]}")
            return None
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        if not quiet:
            print(f"  ✗ aws {cmd}: {e}")
        return None


def get_identity():
    """Get current caller identity."""
    print("\n[1] Caller Identity")
    print("=" * 50)
    data = run_aws("sts get-caller-identity")
    if not data:
        print("  FATAL: Cannot determine identity. Check credentials.")
        sys.exit(1)
    print(f"  Account:  {data.get('Account')}")
    print(f"  ARN:      {data.get('Arn')}")
    print(f"  UserId:   {data.get('UserId')}")
    return data


def get_user_policies(username):
    """Enumerate all policies attached to user."""
    print(f"\n[2] Policies for user: {username}")
    print("=" * 50)
    policies = []

    # Inline policies
    inline = run_aws(f"iam list-user-policies --user-name {username}")
    if inline:
        for name in inline.get("PolicyNames", []):
            print(f"  Inline: {name}")
            pol = run_aws(f"iam get-user-policy --user-name {username} --policy-name {name}")
            if pol:
                policies.append({"type": "inline", "name": name, "document": pol.get("PolicyDocument", {})})

    # Attached managed policies
    attached = run_aws(f"iam list-attached-user-policies --user-name {username}")
    if attached:
        for p in attached.get("AttachedPolicies", []):
            print(f"  Managed: {p['PolicyName']} ({p['PolicyArn']})")
            # Get policy version for actual permissions
            ver = run_aws(f"iam get-policy --policy-arn {p['PolicyArn']}")
            if ver:
                vid = ver["Policy"]["DefaultVersionId"]
                doc = run_aws(f"iam get-policy-version --policy-arn {p['PolicyArn']} --version-id {vid}")
                if doc:
                    policies.append({"type": "managed", "name": p["PolicyName"],
                                     "document": doc.get("PolicyVersion", {}).get("Document", {})})

    # Group policies
    groups = run_aws(f"iam list-groups-for-user --user-name {username}")
    if groups:
        for g in groups.get("Groups", []):
            gname = g["GroupName"]
            print(f"  Group: {gname}")
            gattached = run_aws(f"iam list-attached-group-policies --group-name {gname}")
            if gattached:
                for p in gattached.get("AttachedPolicies", []):
                    print(f"    Managed: {p['PolicyName']}")
                    policies.append({"type": "group_managed", "name": p["PolicyName"], "group": gname})

    return policies


def extract_actions(policies):
    """Extract all allowed actions from policy documents."""
    actions = set()
    for pol in policies:
        doc = pol.get("document", {})
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                act = stmt.get("Action", [])
                if isinstance(act, str):
                    act = [act]
                actions.update(act)
    return actions


def check_escalation_paths(actions):
    """Check discovered permissions against known escalation paths."""
    print("\n[3] Escalation Path Analysis")
    print("=" * 50)
    findings = []

    for required, technique, severity in ESCALATION_PATHS:
        matched = all(
            any(action_matches(a, req) for a in actions)
            for req in required
        )
        if matched:
            findings.append({"permissions": required, "technique": technique, "severity": severity})
            icon = "🔴" if severity == "critical" else "🟠" if severity == "high" else "🟡"
            print(f"  {icon} [{severity.upper()}] {technique}")
            print(f"     Permissions: {', '.join(required)}")

    if not findings:
        print("  No known escalation paths found with current permissions.")

    return findings


def action_matches(action, required):
    """Check if an IAM action matches a required permission (supports wildcards)."""
    if action == "*" or action == "*:*":
        return True
    if "*" in action:
        prefix = action.replace("*", "")
        return required.startswith(prefix)
    return action.lower() == required.lower()


def check_public_resources(account_id):
    """Check for publicly accessible resources."""
    print("\n[4] Public Resource Check")
    print("=" * 50)
    findings = []

    # S3 bucket listing
    buckets = run_aws("s3api list-buckets", quiet=True)
    if buckets:
        for b in buckets.get("Buckets", [])[:20]:
            name = b["Name"]
            acl = run_aws(f"s3api get-bucket-acl --bucket {name}", quiet=True)
            if acl:
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "").endswith("AllUsers") or grantee.get("URI", "").endswith("AuthenticatedUsers"):
                        findings.append({"type": "public_s3", "bucket": name, "permission": grant["Permission"]})
                        print(f"  🔴 PUBLIC S3: {name} ({grant['Permission']})")

            # Check bucket policy for public access
            policy = run_aws(f"s3api get-bucket-policy --bucket {name}", quiet=True)
            if policy:
                pol_doc = json.loads(policy.get("Policy", "{}"))
                for stmt in pol_doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and stmt.get("Principal") in ("*", {"AWS": "*"}):
                        findings.append({"type": "public_s3_policy", "bucket": name})
                        print(f"  🔴 PUBLIC S3 POLICY: {name}")

    # EC2 metadata (check if running on EC2)
    meta = run_aws("ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn]' --output json", quiet=True)
    if meta:
        for instance in meta:
            if instance and len(instance) > 1 and instance[1]:
                print(f"  ℹ Instance {instance[0]} has role: {instance[1]}")

    if not findings:
        print("  No public resources detected (checked S3 ACLs/policies).")

    return findings


def check_assumable_roles():
    """Find roles the current identity can assume."""
    print("\n[5] Assumable Roles")
    print("=" * 50)
    roles = run_aws("iam list-roles --query 'Roles[].{Name:RoleName,Arn:Arn}' --output json", quiet=True)
    assumable = []
    if not roles:
        print("  Cannot list roles (iam:ListRoles denied).")
        return assumable

    identity = run_aws("sts get-caller-identity")
    my_arn = identity.get("Arn", "") if identity else ""

    for role in roles[:50]:  # Cap at 50 to avoid timeout
        role_detail = run_aws(f"iam get-role --role-name {role['Name']}", quiet=True)
        if not role_detail:
            continue
        trust = role_detail.get("Role", {}).get("AssumeRolePolicyDocument", {})
        for stmt in trust.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal", {})
                principals = []
                if isinstance(principal, str):
                    principals = [principal]
                elif isinstance(principal, dict):
                    principals = principal.get("AWS", [])
                    if isinstance(principals, str):
                        principals = [principals]

                if any(p == "*" or my_arn.split("/")[0] in p for p in principals):
                    assumable.append(role)
                    print(f"  ✓ Assumable: {role['Name']} ({role['Arn']})")
                    break

    if not assumable:
        print("  No additional assumable roles found.")
    return assumable


def generate_report(identity, policies, actions, escalations, public_resources, assumable_roles):
    """Generate markdown report."""
    report = f"""# IAM Enumeration Report

**Date:** {datetime.now().isoformat()}
**Account:** {identity.get('Account')}
**Identity:** {identity.get('Arn')}

## Permissions Summary

- **Total actions:** {len(actions)}
- **Admin access:** {'YES 🔴' if '*' in actions or '*:*' in actions else 'No'}
- **Policies:** {len(policies)}

## Escalation Paths ({len(escalations)} found)

| Severity | Technique | Required Permissions |
|----------|-----------|---------------------|
"""
    for e in escalations:
        report += f"| {e['severity'].upper()} | {e['technique']} | {', '.join(e['permissions'])} |\n"

    if public_resources:
        report += f"\n## Public Resources ({len(public_resources)} found)\n\n"
        for r in public_resources:
            report += f"- **{r['type']}**: {r.get('bucket', r.get('resource', 'unknown'))}\n"

    if assumable_roles:
        report += f"\n## Assumable Roles ({len(assumable_roles)} found)\n\n"
        for r in assumable_roles:
            report += f"- {r['Name']} (`{r['Arn']}`)\n"

    report += f"\n## All Discovered Actions\n\n```\n{chr(10).join(sorted(actions))}\n```\n"
    return report


def enumerate(profile=None, output_dir="./ctest-output"):
    """Main enumeration entry point."""
    print("=" * 50)
    print(" ctest IAM Enumeration")
    print("=" * 50)

    identity = get_identity()

    # Extract username from ARN
    arn = identity.get("Arn", "")
    username = None
    if ":user/" in arn:
        username = arn.split(":user/")[-1]
    elif ":assumed-role/" in arn:
        print(f"\n  Running as assumed role. Limited user enumeration.")
        username = None

    policies = []
    actions = set()
    if username:
        policies = get_user_policies(username)
        actions = extract_actions(policies)
        if actions:
            print(f"\n  Total unique actions: {len(actions)}")
            if "*" in actions:
                print("  ⚠️  ADMIN ACCESS DETECTED (*)")
    else:
        print("\n  Skipping user policy enum (role-based identity).")

    escalations = check_escalation_paths(actions) if actions else []
    public_resources = check_public_resources(identity.get("Account"))
    assumable_roles = check_assumable_roles()

    report = generate_report(identity, policies, actions, escalations, public_resources, assumable_roles)

    # Write report
    import os
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "iam-enumeration.md")
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\n{'='*50}")
    print(f"Report written to: {report_path}")
    print(f"Escalation paths: {len(escalations)}")
    print(f"Public resources: {len(public_resources)}")
    print(f"Assumable roles: {len(assumable_roles)}")

    return {
        "identity": identity,
        "actions": list(actions),
        "escalations": escalations,
        "public_resources": public_resources,
        "assumable_roles": assumable_roles,
    }


if __name__ == "__main__":
    enumerate()
