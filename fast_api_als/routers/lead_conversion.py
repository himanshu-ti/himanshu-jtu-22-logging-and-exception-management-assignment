from http.client import HTTPException
import json
from fastapi import APIRouter, Depends
import logging
import time

from fastapi import Request
from starlette import status

from fast_api_als.database.db_helper import db_helper_session
from fast_api_als.quicksight.s3_helper import s3_helper_client
from fast_api_als.services.authenticate import get_token
from fast_api_als.utils.cognito_client import get_user_role

router = APIRouter()

"""
write proper logging and exception handling
"""

def get_quicksight_data(lead_uuid, item):
    """
            Creates the lead converted data for dumping into S3.
            Args:
                lead_uuid: Lead UUID
                item: Accepted lead info pulled from DDB
            Returns:
                S3 data
    """
    
    try:
        data = {
            "lead_hash": lead_uuid,
            "epoch_timestamp": int(time.time()),
            "make": item['make'],
            "model": item['model'],
            "conversion": 1,
            "postalcode": item.get('postalcode', 'unknown'),
            "dealer": item.get('dealer', 'unknown'),
            "3pl": item.get('3pl', 'unknown'),
            "oem_responded": 1
        }
    except KeyError as key_error:
        logging.error("Item doesn't have 'make' or 'model' property")
        raise Exception("Item doesn't have 'make' or 'model' property")
    except Exception as e:
        logging.error("Error trying to extract data from item: %s", e)
        raise Exception("Error trying to extract data from item")

    return data, f"{item['make']}/1_{int(time.time())}_{lead_uuid}"

@router.post("/conversion")
async def submit(file: Request, token: str = Depends(get_token)):
    body = await file.body()
    body = json.loads(str(body, 'utf-8'))

    if 'lead_uuid' not in body or 'converted' not in body:
        logging.info("lead_uuid' or 'converted' not found in body")
        raise HTTPException(400, "'lead_uuid' or 'converted' not found in body")
        
    lead_uuid = body['lead_uuid']
    converted = body['converted']

    oem, role = get_user_role(token)
    if role != "OEM":
        logging.info("role isn't OEM")
        raise HTTPException(400, "role isn't 'OEM'")

    is_updated, item = db_helper_session.update_lead_conversion(lead_uuid, oem, converted)
    if is_updated:
        data, path = get_quicksight_data(lead_uuid, item)
        s3_helper_client.put_file(data, path)
        return {
            "status_code": status.HTTP_200_OK,
            "message": "Lead Conversion Status Update"
        }
    else:
        raise HTTPException(400, "lead_conversion not updated")
