from sqlalchemy import create_engine, Column, Integer, String, DateTime, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

DATABASE_URL = "sqlite:///./cybersentry.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── MODELOS ──

class ScanHistorico(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    hostname = Column(String, nullable=False)
    criado_em = Column(DateTime, default=datetime.datetime.utcnow)
    resultados = Column(JSON, nullable=False)


# ── CRIA TABELAS ──
def init_db():
    Base.metadata.create_all(bind=engine)


# ── DEPENDENCY ──
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()