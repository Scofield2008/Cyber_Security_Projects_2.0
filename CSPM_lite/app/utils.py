from datetime import datetime

def now_iso():
    return datetime.utcnow().isoformat() + 'Z'

def severity_from_issue(issue_type:str):
    mapping = {
        'public_s3': 'HIGH',
        'iam_full_access': 'HIGH',
        'exposed_key_pattern': 'MEDIUM'
    }
def severity_from_issue(issue_type: str):
    mapping = {
        'public_s3': 'HIGH',
        'iam_full_access': 'HIGH',
        'exposed_key_pattern': 'MEDIUM'
    }
    return mapping.get(issue_type, 'LOW')
