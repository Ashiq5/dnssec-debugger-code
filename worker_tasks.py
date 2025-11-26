from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import text
import datetime
import main
import json
import re
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.environ.get("DATABASE_URI")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def run_main(domain: str, record_id: int):
    instr_w_zrep = ""
    instr_wo_zrep = ""
    result = json.loads(main.main(domain))
    if len(result.get("intended_errcodes", [])) == 0:
        instr_wo_zrep = "There exists no misconfiguration in your DNSSEC configuration!"
        instr_w_zrep = "N/A"
        explanations = "N/A"
    else:
        explanations = "\n".join(result.get("explanations", []))
        for hind, iter in enumerate(result.get("instructions_wo_zrep", [])):
            # instr_wo_zrep += "Iteration " + str(hind + 1) + ". "
            instr_wo_zrep += "--------------------\n"
            for h2ind, instr in enumerate(iter):
                instr_wo_zrep += str(h2ind + 1) + ". " + instr + "\n"
        for ind, iteration in enumerate(result.get("fix_transition_errcodes", [])):
            # instr_w_zrep += "Iteration " + str(ind + 1) + ". "
            instr_w_zrep += "--------------------\n"
            fixed_errors_in_this_iteration = list(
                set(iteration["errors_before_fix"]).difference(
                    set(iteration["errors_after_fix"])
                )
            )
            # instr_w_zrep += (
            #     "Fixed "
            #     + ", ".join(fixed_errors_in_this_iteration)
            #     + " errors in this iteration.\n\n"
            # )
            for fixes in iteration.get("fixes", []):
                find = 0
                for fix in fixes.get("instructions", []):
                    if "Suggested" in fix:
                        continue
                    if "Parent zone" in fix:
                        continue
                    if "erroneouszonegeneration.ovh." in fix:
                        fix = re.sub(
                            r"\S*erroneouszonegeneration\.ovh\.", "<ZONE>", fix
                        )
                    # elif "erroneouszonegeneration.ovh" in fix:
                    #     fix = re.sub(
                    #         r"\S*erroneouszonegeneration\.ovh*", "<ZONE>", fix
                    #     )
                    instr_w_zrep += str(find + 1) + ". " + fix + "\n"
                    find = find + 1
        # if len(result.get("after_fix_errcodes", [])) > 0:
        #     instr_w_zrep += "Note that DFixer could not resolve all the error codes"
        if not instr_w_zrep:
            instr_w_zrep = "Sorry, something went wrong in DFixer. Please try again."

    # Update database with result
    db = SessionLocal()
    db.execute(
        text(
            "UPDATE requests SET status='Completed', instr_wo_zrep=:instr_wo_zrep, instr_w_zrep=:instr_w_zrep,\
            explanations=:explanations, completed_at=:time WHERE id=:id"
        ),
        {
            "instr_w_zrep": instr_w_zrep,
            "instr_wo_zrep": instr_wo_zrep,
            "explanations": explanations,
            "time": datetime.datetime.utcnow(),
            "id": record_id,
        },
    )
    db.commit()
    db.close()
