from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from backend.database import Base, engine, get_db
from backend.models import RequestLog
from redis import Redis
import os
import rq
import uuid
from datetime import timezone

# Create tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(title="DNSSEC Debugger Web")
redis_conn = Redis(host="localhost", port=6379, decode_responses=True)
queue = rq.Queue("main_tasks", connection=redis_conn)

# ---- Correct frontend path setup ----
# 1️⃣ Get the absolute path to the directory where this file is located
current_dir = os.path.dirname(os.path.abspath(__file__))

# 2️⃣ Go one level up to the project root (where 'frontend' lives)
project_root = os.path.dirname(current_dir)

# 3️⃣ Build the absolute path to the 'frontend' directory
frontend_dir = os.path.join(current_dir, "frontend")
print(current_dir, project_root, frontend_dir)
# app.mount("/static", StaticFiles(directory=frontend_path), name="static")


# Serve HTML endpoints "/"
@app.get("/")
def serve_index():
    index_path = os.path.join(frontend_dir, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path)


@app.get("/dfixer")
def serve_dfixer_result():
    filepath = os.path.join(frontend_dir, "dfixer.html")
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(filepath, media_type="text/html")


class RunRequest(BaseModel):
    domain: str


def format_timestamp_utc(dt) -> str:
    """Convert a datetime (naive or offset-aware) to UTC and format as 'YYYY-MM-DD HH:MM:SS UTC'."""
    if dt is None:
        return "Invalid date"

    # If naive datetime, assume it's in local time (convert to UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # Convert to UTC and format
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")


@app.post("/run")
def run(req: RunRequest, db: Session = Depends(get_db)):
    # Save to database
    job_id = str(uuid.uuid4())
    record = RequestLog(
        domain=req.domain, output="Processing...", status="Queued", job_id=job_id
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Push job to Redis
    job = queue.enqueue("worker_tasks.run_main", req.domain, record.id, job_id=job_id)
    job_url = f"/dfixer?job_id={job_id}"

    return {"job_id": job.get_id(), "status": "Queued", "result_url": job_url}


@app.get("/history")
def get_history(db: Session = Depends(get_db)):
    records = (
        db.query(RequestLog).order_by(RequestLog.created_at.desc()).limit(20).all()
    )
    return [
        {
            "id": r.id,
            "domain": r.domain,
            "output": r.output,
            "status": r.status,
            "created_at": r.created_at,
            "complete_at": r.completed_at,
        }
        for r in records
    ]


@app.get("/result/{job_id}")
def get_result(job_id: str, db: Session = Depends(get_db)):
    record = db.query(RequestLog).filter(RequestLog.job_id == job_id).first()
    if record:
        return {
            "status": record.status,
            "domain": record.domain if record else None,
            "output": record.output if record else None,
            "created_at": format_timestamp_utc(record.created_at),
        }
    else:
        return {
            "status": "Unavailable",
        }
