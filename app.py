from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from backend.database import Base, engine, get_db
from backend.models import RequestLog
from redis import Redis
import os
import rq
from worker_tasks import run_main

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


# Serve index.html at root "/"
@app.get("/")
def serve_index():
    index_path = os.path.join(frontend_dir, "index.html")
    if not os.path.exists(index_path):
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(index_path)


class RunRequest(BaseModel):
    domain: str


@app.post("/run")
def run(req: RunRequest, db: Session = Depends(get_db)):
    # Save to database
    record = RequestLog(domain=req.domain, output="Processing...", status="Queued")
    db.add(record)
    db.commit()
    db.refresh(record)

    # Fake computation or call to your main.py logic
    # Replace this block with your actual logic
    # output = f"Processed domain: {req.domain} at {datetime.utcnow()}"
    # Push job to Redis
    job = queue.enqueue("worker_tasks.run_main", req.domain, record.id)
    print("job_id", job.get_id(), "status", "queued", req.domain, record.id)
    return {"job_id": job.get_id(), "status": "queued"}
    # return {"id": record.id, "domain": record.domain, "output": record.output, "created_at": record.created_at}


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
