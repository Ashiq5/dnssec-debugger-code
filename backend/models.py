from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID
from .database import Base
import uuid


class RequestLog(Base):
    __tablename__ = "requests"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), nullable=False)
    output = Column(Text)
    status = Column(String(100))
    job_id = Column(UUID(as_uuid=True), unique=True, nullable=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), server_default=func.now())
