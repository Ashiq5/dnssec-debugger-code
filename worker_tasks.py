import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text
import datetime
import main
import json
import re


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
    output = ""
    result = json.loads(main.main(domain))
    if len(result["intended_errcodes"]) == 0:
        output = "No DNSSEC errors to fix, congratulations!"
    else:
        for ind, iteration in enumerate(result.get("fix_transition_errcodes", [])):
            output += "Iteration " + str(ind + 1) + ". "
            fixed_errors_in_this_iteration = list(set(iteration["errors_before_fix"]).difference(set(iteration["errors_after_fix"])))
            output += "Fixed " + ", ".join(fixed_errors_in_this_iteration) + " errors in this iteration.\n\n"
            for fixes in iteration.get("fixes", []):
                find = 0
                for fix in fixes.get("instructions", []):
                    if "Parent zone" in fix:
                        continue
                    if "erroneouszonegeneration.ovh" in fix:
                        fix = re.sub(r'\S*erroneouszonegeneration\.ovh\S*', '<ZONE>', fix)
                    output += str(find + 1) + ". " + fix + "\n"
                    find = find + 1
        if not output:
            output = "Sorry, something went wrong in DFixer. Please try again."

    # Update database with result
    db = SessionLocal()
    db.execute(
        text(
            "UPDATE requests SET status='Completed', output=:output, completed_at=:time WHERE id=:id"
        ),
        {
            "output": output,
            "time": datetime.datetime.utcnow(),
            "id": record_id,
        },
    )
    db.commit()
    db.close()
