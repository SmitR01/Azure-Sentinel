"""This __init__ file will be called once triggered is generated."""
import time

import azure.functions as func

from ..SharedCode.logger import applogger
from .bitsight_companies import BitSightCompanies


def main(mytimer: func.TimerRequest) -> None:
    """Start the execution.

    Args:
        mytimer (func.TimerRequest): timer trigger
    """
    applogger.info("BitSight: Companies_Details: Start processing...")
    start = time.time()
    bitsightcompanies_obj = BitSightCompanies(start)
    bitsightcompanies_obj.get_bitsight_data_into_sentinel()
    end = time.time()
    applogger.info(
        "BitSight: time taken for data ingestion is {} sec".format(int(end - start))
    )
    applogger.info("BitSight: Companies_Details: execution completed.")
    if mytimer.past_due:
        applogger.info("The timer is past due!")
