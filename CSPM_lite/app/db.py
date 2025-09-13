# app/db.py
import os
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cspm.db")

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, index=True)
    resource = Column(String)
    issue = Column(String)
    recommendation = Column(String)


def init_db():
    Base.metadata.create_all(bind=engine)


def save_result(provider: str, resource: str, issue: str, recommendation: str):
    """Save a scan result into the database"""
    session = SessionLocal()
    result = ScanResult(
        provider=provider,
        resource=resource,
        issue=issue,
        recommendation=recommendation
    )
    session.add(result)
    session.commit()
    session.refresh(result)
    session.close()
    return result


def get_results():
    """Fetch all scan results"""
    session = SessionLocal()
    results = session.query(ScanResult).all()
    session.close()
    return results
