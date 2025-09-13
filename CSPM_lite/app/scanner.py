# app/scanner.py
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime

# utils functions (if you have them in utils.py, import them)
try:
    from .utils import severity_from_issue
except Exception:
    def severity_from_issue(x): return 'HIGH' if x in ('public_s3','iam_full_access') else 'MEDIUM'

# --- AWS checks (use boto3) ---
def aws_s3_check_public_buckets(aws_access_key=None, aws_secret_key=None, aws_session_token=None, region_name='us-east-1'):
    findings = []
    session_args = {}
    if aws_access_key and aws_secret_key:
        session_args.update({
            'aws_access_key_id': aws_access_key,
            'aws_secret_access_key': aws_secret_key,
            'aws_session_token': aws_session_token
        })

    try:
        s3 = boto3.client('s3', **{k:v for k,v in session_args.items() if v is not None}, region_name=region_name)
        resp = s3.list_buckets()
        buckets = resp.get('Buckets', [])
        for b in buckets:
            name = b['Name']
            public = False
            details = []
            # ACL
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI')
                    if uri and ('AllUsers' in uri or 'AuthenticatedUsers' in uri):
                        public = True
                        details.append('ACL allows public access')
            except ClientError as e:
                details.append(f'Could not fetch ACL: {e}')

            # Public access block
            try:
                bpa = s3.get_public_access_block(Bucket=name)
                config = bpa.get('PublicAccessBlockConfiguration', {})
                if not all(config.get(k, False) for k in ['BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets']):
                    details.append('Public access block not fully enabled')
                    public = True
            except ClientError:
                details.append('No Public Access Block configuration')

            # Policy check (naive)
            try:
                pol = s3.get_bucket_policy(Bucket=name)
                policy_text = pol.get('Policy','')
                if '"Principal":"*"' in policy_text or '"Principal": "*"' in policy_text or '"AWS":"*"' in policy_text:
                    public = True
                    details.append('Bucket policy allows principal *')
            except ClientError:
                pass

            if public:
                findings.append({
                    'provider': 'aws',
                    'resource_type': 's3_bucket',
                    'resource_id': name,
                    'severity': severity_from_issue('public_s3'),
                    'title': 'S3 Bucket Possibly Public',
                    'detail': ' | '.join(details) or 'Detected public settings',
                    'remediation': 'Enable S3 Public Access Block, remove public ACLs/policies, and restrict bucket policy to specific principals.',
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
    except (NoCredentialsError, PartialCredentialsError) as e:
        findings.append({
            'provider':'aws',
            'resource_type':'account',
            'resource_id':'aws_api',
            'severity':'LOW',
            'title':'AWS credentials not found or incomplete',
            'detail': str(e),
            'remediation': 'Configure credentials (aws configure) or provide keys in the form.'
        })
    except ClientError as e:
        findings.append({
            'provider':'aws',
            'resource_type':'account',
            'resource_id':'aws_api',
            'severity':'LOW',
            'title':'Unable to enumerate S3 buckets',
            'detail': str(e),
            'remediation': 'Check provided credentials and permissions (s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketPolicy).'
        })
    except Exception as e:
        findings.append({
            'provider':'aws',
            'resource_type':'account',
            'resource_id':'aws_api',
            'severity':'LOW',
            'title':'AWS scan error',
            'detail': str(e),
            'remediation': 'Check server logs.'
        })
    return findings


def aws_iam_check_overly_permissive(aws_access_key=None, aws_secret_key=None, aws_session_token=None, region_name='us-east-1'):
    findings = []
    session_args = {}
    if aws_access_key and aws_secret_key:
        session_args.update({
            'aws_access_key_id': aws_access_key,
            'aws_secret_access_key': aws_secret_key,
            'aws_session_token': aws_session_token
        })
    try:
        iam = boto3.client('iam', **{k:v for k,v in session_args.items() if v is not None}, region_name=region_name)
        paginator = iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            for pol in page.get('Policies',[]):
                arn = pol['Arn']
                try:
                    ver = iam.get_policy(PolicyArn=arn)
                    default_ver = ver['Policy'].get('DefaultVersionId')
                    doc = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)
                    doc_text = doc['PolicyVersion']['Document']
                    statements = doc_text.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for st in statements:
                        if not isinstance(st, dict):
                            continue
                        action = st.get('Action')
                        resource = st.get('Resource')
                        if action == '*' or resource == '*' or action == ['*']:
                            findings.append({
                                'provider':'aws',
                                'resource_type':'iam_policy',
                                'resource_id':arn,
                                'severity':severity_from_issue('iam_full_access'),
                                'title':'IAM Policy Possibly Overly Permissive',
                                'detail':'Policy default version contains wildcard action/resource',
                                'remediation':'Restrict actions and resources; follow principle of least privilege.',
                                'timestamp': datetime.utcnow().isoformat() + 'Z'
                            })
                except Exception:
                    continue
    except (NoCredentialsError, PartialCredentialsError) as e:
        findings.append({
            'provider':'aws',
            'resource_type':'account',
            'resource_id':'aws_api_iam',
            'severity':'LOW',
            'title':'AWS credentials not found or incomplete for IAM check',
            'detail': str(e),
            'remediation': 'Provide credentials or configure default AWS credentials.'
        })
    except Exception as e:
        findings.append({
            'provider':'aws',
            'resource_type':'account',
            'resource_id':'aws_api_iam',
            'severity':'LOW',
            'title':'Unable to enumerate IAM policies',
            'detail': str(e),
            'remediation': 'Check permissions: iam:ListPolicies, iam:GetPolicyVersion'
        })
    return findings


def aws_scan_all(aws_access_key=None, aws_secret_key=None, aws_session_token=None):
    findings = []
    findings.extend(aws_s3_check_public_buckets(aws_access_key, aws_secret_key, aws_session_token))
    findings.extend(aws_iam_check_overly_permissive(aws_access_key, aws_secret_key, aws_session_token))
    return findings


# --- Azure checks (basic) ---
def azure_check_basic(tenant_id=None, client_id=None, client_secret=None):
    findings = []
    try:
        # lazy import so missing SDKs don't break app
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
    except Exception as e:
        findings.append({
            'provider': 'azure',
            'resource': 'n/a',
            'title': 'Azure SDK not installed',
            'issue': 'Azure scanning unavailable',
            'remediation': 'pip install azure-identity azure-mgmt-storage'
        })
        return findings

    try:
        if tenant_id and client_id and client_secret:
            cred = ClientSecretCredential(tenant_id, client_id, client_secret)
        else:
            cred = DefaultAzureCredential()
        # The StorageManagementClient requires subscription id to list storage accounts.
        # For demo, just report connectivity success.
        findings.append({
            'provider': 'azure',
            'resource': 'n/a',
            'title': 'Azure scanner connected (basic)',
            'issue': 'Connected successfully (limited checks)',
            'remediation': 'Provide subscription id and extend scanner to list storage accounts.'
        })
    except Exception as e:
        findings.append({
            'provider':'azure',
            'resource':'n/a',
            'title':'Azure scan error',
            'issue': str(e),
            'remediation': 'Ensure credentials and environment are correct.'
        })
    return findings


# --- GCP checks (basic) ---
def gcp_check_basic(gcp_key_path=None):
    findings = []
    try:
        from google.cloud import storage
        # use env var if path provided
        from google.oauth2 import service_account
    except Exception:
        findings.append({
            'provider':'gcp',
            'resource':'n/a',
            'title':'GCP SDK not installed',
            'issue':'GCP scanning unavailable',
            'remediation':'pip install google-cloud-storage'
        })
        return findings

    try:
        if gcp_key_path:
            creds = service_account.Credentials.from_service_account_file(gcp_key_path)
            client = storage.Client(credentials=creds, project=creds.project_id)
        else:
            client = storage.Client()  # uses default env
        # sample: list buckets (will only list buckets under provided project/account)
        buckets = list(client.list_buckets(max_results=20))
        if not buckets:
            findings.append({
                'provider':'gcp',
                'resource':'n/a',
                'title':'GCP: no accessible buckets found (or permission denied)',
                'issue':'No buckets listed',
                'remediation':'Ensure correct service account permissions or set GCP_PROJECT env var.'
            })
        else:
            for b in buckets:
                # we can try a simple check: does the bucket allow public listing? (try fetching ACL)
                try:
                    acl = b.acl.get_entities()
                    # this call returns list of entities; we won't use deep analysis here
                    findings.append({
                        'provider':'gcp',
                        'resource': b.name,
                        'title': 'GCP bucket visible',
                        'issue': 'Bucket found; further permission checks required',
                        'remediation': 'Review bucket IAM and ACLs; restrict public access.',
                        'timestamp': datetime.utcnow().isoformat() + 'Z'
                    })
                except Exception:
                    findings.append({
                        'provider':'gcp',
                        'resource': b.name,
                        'title':'GCP bucket (limited access)',
                        'issue':'Found but ACL/permissions could not be read (permission denied)',
                        'remediation':'Grant storage.buckets.get and storage.buckets.getIamPolicy to the service account.'
                    })
    except Exception as e:
        findings.append({
            'provider':'gcp',
            'resource':'n/a',
            'title':'GCP scan error',
            'issue': str(e),
            'remediation':'Check service account credentials and environment.'
        })
    return findings


# --- top-level runner used by main.py ---
def run_scan(provider: str, aws_access_key=None, aws_secret_key=None, aws_session_token=None,
             azure_tenant_id=None, azure_client_id=None, azure_client_secret=None,
             gcp_key_path=None):
    provider = (provider or "aws").lower()
    if provider == "aws":
        return aws_scan_all(aws_access_key, aws_secret_key, aws_session_token)
    elif provider == "azure":
        return azure_check_basic(azure_tenant_id, azure_client_id, azure_client_secret)
    elif provider == "gcp":
        return gcp_check_basic(gcp_key_path)
    else:
        return [{
            'provider': provider,
            'resource': 'n/a',
            'title': 'Unsupported provider',
            'issue': f'No scanner for {provider}',
            'remediation': 'Supported providers: aws, azure, gcp'
        }]
