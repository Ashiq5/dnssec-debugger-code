import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text
import datetime
import main
import json


# --- Database setup ---
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "postgres")
DB_HOST = os.getenv("POSTGRES_HOST_FROM_DOCKER", "host.docker.internal")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "dnssec_debugger")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def run_main(domain: str, record_id: int):
    # Run your main.py logic
    # result = subprocess.run(
    #     ["python3", "/data/ErroneousZoneGeneration/main.py", "--resolve", domain],
    #     capture_output=True,
    #     text=True,
    #     timeout=600,
    # )
    #
    # output_text = result.stdout.strip() or result.stderr.strip()

    # todo: need some manipulation in case of empty
    instructions = []
    result = json.loads(main.main(domain))
    for iteration in result["fix_transition_errcodes"]:
        for fixes in iteration["fixes"]:
            for fix in fixes["instructions"]:
                # print(iteration["instructions"], type(iteration["fixes"]))
                instructions.append(fix)

    # Update database with result
    db = SessionLocal()
    db.execute(
        text(
            "UPDATE requests SET status='Done', output=:output, completed_at=:time WHERE id=:id"
        ),
        {
            "output": "".join(instructions),
            "time": datetime.datetime.utcnow(),
            "id": record_id,
        },
    )
    db.commit()
    db.close()
