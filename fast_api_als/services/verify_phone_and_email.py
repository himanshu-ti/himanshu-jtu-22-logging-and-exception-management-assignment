import time
import httpx
import asyncio
import logging
from fast_api_als.constants import (
    ALS_DATA_TOOL_EMAIL_VERIFY_METHOD,
    ALS_DATA_TOOL_PHONE_VERIFY_METHOD,
    ALS_DATA_TOOL_SERVICE_URL,
    ALS_DATA_TOOL_REQUEST_KEY)

"""
How can you write log to understand what's happening in the code?
You also trying to undderstand the execution time factor.
"""

logging.basicConfig(format = '%(levelname)s %(asctime)s %(message)s')

async def call_validation_service(url: str, topic: str, value: str, data: dict) -> None:  # 2
    start  = time.process_time()
    if value == '':
        return
    async with httpx.AsyncClient() as client:  # 3
        logging.info("Awaiting client response")
        response = await client.get(url)
        logging.info("Got client response")

    r = response.json()
    data[topic] = r
    time_taken = (time.process_time() - start) * 1000
    logging.info("call_validation_service: Took %f ms", time_taken)
    

async def verify_phone_and_email(email: str, phone_number: str) -> bool:
    email_validation_url = '{}?Method={}&RequestKey={}&EmailAddress={}&OutputFormat=json'.format(
        ALS_DATA_TOOL_SERVICE_URL,
        ALS_DATA_TOOL_EMAIL_VERIFY_METHOD,
        ALS_DATA_TOOL_REQUEST_KEY,
        email)
    phone_validation_url = '{}?Method={}&RequestKey={}&PhoneNumber={}&OutputFormat=json'.format(
        ALS_DATA_TOOL_SERVICE_URL,
        ALS_DATA_TOOL_PHONE_VERIFY_METHOD,
        ALS_DATA_TOOL_REQUEST_KEY,
        phone_number)
    email_valid = False
    phone_valid = False
    data = {}

    logging.info("Starting Email and Phone validation service")
    await asyncio.gather(
        call_validation_service(email_validation_url, "email", email, data),
        call_validation_service(phone_validation_url, "phone", phone_number, data),
    )
    logging.info("Received response from Email and Phone validation service")

    try:    
        if "email" in data:
            if data["email"]["DtResponse"]["Result"][0]["StatusCode"] in ("0", "1"):
                logging.info("Valid Email %s", data)
                email_valid = True
        if "phone" in data:
            if data["phone"]["DtResponse"]["Result"][0]["IsValid"] == "True":
                logging.info("Valid Phone Number")
                phone_valid = True
    except KeyError as key_error:
        logging.error("Data doesn't contain key %s", key_error)
        raise Exception("Data in incorrect form")
    except Exception as e:
        logging.error("Error occurred %s", e)
        raise Exception(e)
        
    return email_valid | phone_valid    