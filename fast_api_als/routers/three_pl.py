import json
import logging
from fastapi import Request

from fastapi import APIRouter, HTTPException, Depends
from fast_api_als.database.db_helper import db_helper_session
from fast_api_als.services.authenticate import get_token
from fast_api_als.utils.cognito_client import get_user_role
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED

router = APIRouter()
logging.basicConfig(format='%(levelname)s %(asctime)s %(message)s')

@router.post("/reset_authkey")
async def reset_authkey(request: Request, token: str = Depends(get_token)):
    body = await request.body()
    body = json.loads(body)
    provider, role = get_user_role(token)
    if role != "ADMIN" and (role != "3PL"):
        logging.info("Unprevileged User %s : %s", provider, role)
        raise HTTPException(401, "Unprevileged User")
    if role == "ADMIN":
        provider = body['3pl']
    
    apikey = db_helper_session.set_auth_key(username=provider)
    logging.info("Auth Key set for %s", provider)
    
    return {
        "status_code": HTTP_200_OK,
        "x-api-key": apikey
    }


@router.post("/view_authkey")
async def view_authkey(request: Request, token: str = Depends(get_token)):
    body = await request.body()
    body = json.loads(body)
    provider, role = get_user_role(token)

    if role != "ADMIN" and role != "3PL":
        logging.info("Unprevileged User %s : %s", provider, role)
        raise HTTPException(401, "Unprevileged User")
    if role == "ADMIN":
        provider = body['3pl']
    
    apikey = db_helper_session.get_auth_key(username=provider)
    logging.info("Auth Key get for %s", provider)
    
    return {
        "status_code": HTTP_200_OK,
        "x-api-key": apikey
    }
