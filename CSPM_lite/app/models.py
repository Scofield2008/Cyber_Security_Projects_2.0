# app/models.py
from datetime import datetime
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class FindingDB(Base):
    __tablename__ = 'findings'
    id = Column(Integer, primary_key=True)
    provider = Column(String, nullable=False)
    resource_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    detail = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class ScanResult(BaseModel):
    provider: str
    findings: List[dict]

class ScanRequest(BaseModel):
    provider: str
    aws_access_key: Optional[str]
    aws_secret_key: Optional[str]
    aws_session_token: Optional[str]