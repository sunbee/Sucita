from fastapi import FastAPI, Query, Path, File, UploadFile, HTTPException, Depends, Cookie, Response, Header, status
from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel, HttpUrl, Field, EmailStr
import os
import requests
from requests.exceptions import HTTPError
import FireCRUD
import re
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

# Use: !openssl rand -hex 32 
SECRET_KEY = "a3fd9fedc2a668a4dce66e5c06aef2ac832c1cd92e7e89e404499542b4d06cac"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(password_plain, password_hashed):
    """
    Verify the plain-text password by comparing with the expected (hashed) password.
    """
    return pwd_context.verify(password_plain, password_hashed)

def get_hashed_password(password_plain):
    """
    Hash a plain-text password.
    """
    return pwd_context.hash(password_plain)

def authenticate_user(user_DB, username: str, password: str):
    """
    Check that the username and password are correct.
    Return user's data as an object of UserInDB (pydantic) class.
    """
    user = get_user_by_nmme(user_DB, username)
    if not user:
        return False
    if not verify_password(password, user.password_hashed):
        return False
    return user

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

def create_acccess_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expiry_time = datetime.utcnow() + expires_delta
    else:
        expiry_time = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expiry_time})
    encoded_JWT = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)    
    return encoded_JWT

class UserBase(BaseModel):
    username: str
    email: EmailStr
    fullname: Optional[str] = None
    disabled: Optional[bool] = None

class UserIn(UserBase):
    password: str

class UserOut(UserBase):
    pass

class UserInDB(UserBase):
    password_hashed: str

yojaka_db = {
    "Shiva": {
        "username": "Shiva",
        "email": "shiva6shakti9@kailashparvat.com",
        "disabled": False,
        "password_hashed": get_hashed_password("gangadhara")
    },
    "Shakti": {
        "username": "Shakti",
        "email": "ganapathi_mom@kailashparvat.com",
        "disabled": True,
        "password_hashed": get_hashed_password("3!3ph@ntH3@d")
    },
    "Ganapathi": {
        "username": "Ganapathi",
        "email": "bappa.morya@modak.com",
        "disabled": False,
        "password_hashed": get_hashed_password("gajanana")
    }
}

def hash_password(password: str):
    """
    MARKED FOR DEPRACATION

    Hash a password for demonstration of OAuth2 flow.
    Deprecate at earliest amd use: get_hashed_password().
    """
    return password+"#"

def create_user(user_in: UserIn):
    """
    Create a new user account and store the password securely in the database.
    Use the get_hashed_password function to hash the password.
    """
    user_in_DB = UserInDB(**user_in.dict(), password_hashed=get_hashed_password(user_in.password))
    yojaka_db[user_in.username] = user_in_DB.dict()
    return user_in_DB

class Item(BaseModel):
    image: HttpUrl = Field(..., example="https://srajahiyer.files.wordpress.com/2016/05/img_20160505_171720.jpg")
    document: Optional[HttpUrl] = Field(None, description = "Associate a document with the image for search corpus.")
    tags: str = Field(..., description="Provide tags as a comma-separated list to use in search.", example="shiva,mahadev,goa")

    class Config:
        schema_extra = {
            "example": {
                "image": "https://en.wikipedia.org/wiki/Mount_Kailash#/media/File:Kailash-Barkha.jpg",
                "tags": "mahadev,shambho,kailash,himalaya"
             }
         }

class Item_DB(Item):
    id: int

class Item_Update(BaseModel):
    document: Optional[HttpUrl] = Field(None, description="Optionally update the linked document.")
    tags: str = Field(..., description="Update the tags, replacing old ones.", example="manguesh,shiva,guru,goa")

    class Config:
        schema_extra = {
            "example": {
                "document": "https://en.wikipedia.org/wiki/Mount_Kailash#/media/File:Kailash-Barkha.jpg",
                "tags": "adiyogi"
             }
         }

app = FastAPI()

@app.post("/token")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Handle the authentication flow wehn user submits credentials. 
    The flow is as follows:
    1. Accept the username and password from user via form.
    2. Check that the account exists, or raise error.
    3. Check that the password is correct, or raise error.
    4. Issue token as JSON compliant with specification.

    Refactored to work with JWT as follows:
    1. Used the authenticate_user function to verify credentials and get user profile.
    2. Used create_access_token function to make a JWT token.
    """
    user = authenticate_user(yojaka_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Presented invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token = create_acccess_token(
        data={"subject": user.username}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRES_MINUTES)
    )

    return {"access_token": access_token, "token_type": "bearer"}

    """ DEPRECATED
    user_dict = yojaka_db.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password.")
    user = UserInDB(**user_dict)
    password_hashed = hash_password(form_data.password)
    if not password_hashed == user.password_hashed:
        raise HTTPException(status_code=400, detail="Incoorect username or password.")

    return {"access_token": user.username, "token_type": "bearer"}
    """

@app.post("/user/", response_model=UserOut, tags=["Manage User Accounts"])
async def add_user(user: UserIn):
    user_added = create_user(user)
    return user_added
    
sucita_db = [{
    'id': 1,
    'image': 'https://i0.wp.com/hindupad.com/wp-content/uploads/2011/02/lord-mangesh-in-priol-near-panda-in-goa2.jpg',
    'document': None,
    'tags': 'manguesh,goa,shiva,bhakti'
}, {
    'id': 2,
    'image': 'https://srajahiyer.files.wordpress.com/2016/05/img_20160505_171720.jpg',
    'document': None,
    'tags': 'kukkesubrahmanya,karnataka'
}, {
    'id': 3,
    'image': 'http://www.travelpeopleindia.in/wp-content/uploads/2019/01/Temples-in-Goa-0_b9swzb.jpg',
    'document': None,
    'tags': 'mahadev,temple,goa,shiva'
}]

@app.get('/', tags=["Sandbox"])
async def root():
    return {"message": "Howdy Universe"}

@app.get('/tags', tags=["Sandbox"])
async def get_tags():
    return {"tags": "india, king, tango"}

async def query_extractor(q: Optional[str] = None):
    return q

async def query_or_cookie_extractor(q: str = Depends(query_extractor), last_query: Optional[str] = Cookie(None)):
    if not q:
        return last_query
    return q 

async def verify_token(x_token: str = Header(...)):
    if not x_token == "Om_Namah_Shivaya":
        raise HTTPException(status_code=404, detail="Got no valid token: {x_token}.")

async def verify_key(x_key: str = Header(...)):
    if not x_key == "Har_Har_Mahadev":
        raise HTTPException(status_code=404, detail="Got no valid key: {x_key}.")
    return x_key

@app.get('/users/', tags=["Sandbox"], dependencies=[Depends(verify_token), Depends(verify_key)])
async def get_users(*, query_or_cookie: str = Depends(query_or_cookie_extractor), response: Response):
    """
    Implement a primitive form of authentication using headers.
    Use dependency injection to authenticate headers: x_token, x_key
    These must have the correct values or auth will fail.
    For demonstration only!
    """
    response.set_cookie(key = "last_query", value = query_or_cookie)
    return {"query_or_cookie": query_or_cookie}

class CNN(str, Enum):
    alexnet = "alexnet"
    resnet = "resnet"
    lenet = "lenet"

def get_user_by_nmme(leDB, name: str):
    """
    Look up a user by name and retrieve user's profile.
    The database is a dictionary. 
    Returns the user's profile as an object of UserInDB (pydantdic) class.
    Use mainly in authentication flow.
    """
    print(name)
    user_dict = leDB.get(name)
    if user_dict:
        return UserInDB(**user_dict)

def fake_decode_token(token):
    """
    MARKED FOR DEPRECATION

    Use the user's username attribute as the token in auth flow.
    Deprecate at the earliest and use JWT standard.
    """
    user_me = get_user_by_nmme(yojaka_db, token)
    return user_me

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Decode the JWT token and extract the user or raise an error.
    Executes the following steps:
    1. Decodes the JWT token bearing the username as subject.
    2. Extracts the user's profile from the database.
    3. Returns the user or raises an exception.
    Note:
    Refactored from demonstration scheme as follows:
    1. Added a exception_credentials object of class HTTPException.
    2. Updated decoding token to use JWT instead of primitive string operation.
    3. Implemented a try-except scheme to trap errors.
    """
    exception_credentials = HTTPException(
        status_code=401,
        detail="Granted no access.",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("subject")
        if not username:
            raise exception_credentials
    except JWTError:
        raise exception_credentials
    user = get_user_by_nmme(yojaka_db, username)
    if not user:
        raise exception_credentials
    return user

    """ DEPRECATED
    user_me = fake_decode_token(token)
    if not user_me:
        raise HTTPException(
            status_code=400, 
            detail="Invalid authentication credentials.", 
            headers={"WWW-Authenticate": "Bearer"})
    return user_me
    """

async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="{current_user.username} has an inactive account.")
    return current_user

@app.get('/users/me', tags=['Manage User Accounts'], response_model=UserOut)
async def read_users_me(current_user: UserOut = Depends(get_current_active_user)):
    return current_user

@app.get("/cnn/{model_name}", tags=["Sandbox"], deprecated=True)
async def get_CNN(model_name: CNN):
    ret = None
    if (model_name == CNN.alexnet):
        ret = {"model": model_name, "message": "Delve in Deep"}
    elif (model_name.value == "resnet"):
        ret = {"model": model_name, "message": "Crafty Convolutions"}
    elif (model_name.value == "lenet"):
        ret = {"model": model_name, "message": "Reframe Recurrence"} 
    return ret

@app.get('/item/{ID}', response_model = UserOut, tags=["Manage Records"], summary="Get a record by ID. Experimental!")
async def get_item(ID: int, current_user: UserOut = Depends(get_current_active_user)):
    return current_user

@app.get("/items", tags=["Manage Records"], summary="Find records in the collection.")
async def get_db(skip: int = 0, limit: int = 3, 
q: Optional[List[str]] = Query(None, description="Pass the tags you want to retrieve images by.")):
    """
    Find records in the collection. Search with:

    - **q** - search with this tag. Specify as many as you need to narrow search or none to see entire contents.
    - **skip** - skip this many records from the start.
    - **limit** -  show this many results.

    """
    search_scope = sucita_db.copy()
    search_result = [Dict]
    if q:
        search_terms = q # list of search terms
        while True:
            search_term = search_terms.pop()
            matches = [record for record in search_scope if search_term in record["tags"].split(",")]
            search_scope = matches
            if len(matches) == 0:
                break;
            if len(search_terms) == 0:
                break;
    return search_scope[skip:skip+limit]

@app.post("/items/", response_model=Item_DB, tags=["Manage Records"], deprecated=True)
async def add_item(item: Item):
    new_item = item.dict()
    new_item["id"] = len(sucita_db) + 1
    sucita_db.append(new_item)
    print(new_item)
    return new_item # dict

@app.put("/items/{ID}", response_model=Item_DB, tags=["Manage Records"], summary="Modify a record.")
async def update_item(*, ID: int = Path(..., ge=1), item: Item_Update):
    """
    Modify a record with the specified ID. You can modify:

    - **tags** - replace the old tags with new ones. Note that the old tags will be deleted.
    - **document** - a URL for the document associated with the record.

    You cannot change the image, once uploaded.
    """
    selected_item = [record for record in sucita_db if record["id"]==ID]
    if not selected_item:
        raise HTTPException(status_code=404, detail=f"Found no item with {ID}.")
    else:
        selected_item = selected_item[0]
    if not selected_item:
        return {"item": selected_item}
    if item.document:
        selected_item["document"] = item.document
    if item.tags:
        selected_item["tags"] = item.tags
    return selected_item # dict

@app.delete("/items/{ID}", response_model=Item_DB, tags=["Manage Records"], summary="Delete a record.")
async def delete_item(ID: int = Path(..., ge=1)):
    """
    Delete a record from the database. 
    You will need to provide the record's ID. You can use 
    the search feature to locate the document. Note that
    deletion is permanent and cannot be undone.
    """
    selected_item = [record for record in sucita_db if record["id"] == ID]
    if not selected_item:
        raise HTTPException(status_code=404, detail=f"Found no item with {ID}.")
    selected_item = selected_item[0]
    url2delete = selected_item["image"]
    url2delete = re.findall("(^[^?]*)", url2delete)[0]
    print(url2delete)

    try:
        token_Firebase = FireCRUD.get_authToken()
    except HTTPError as errHTTP:
        raise HTTPException(status_code=404, detail=f'Got no token from Firebase. See: {errHTTP}')
    except Exception as err:
        raise HTTPException(status_code=404, detail=f'Got no auth token. See: {err}')
    else:
        print(token_Firebase)
        headers = {"Authorization": "Bearer "+token_Firebase["idToken"]}

        try:
            r = requests.delete(url2delete, headers=headers)
            r.raise_for_status()
        except HTTPError as errHTTP:
            raise HTTPException(status_code=404, detail=f'Firebase removed no image. See: {errHTTP}')
        except Exception as err:
            raise HTTPException(status_code=404, detail=f'Removed no image. See: {err}')
        else:           
            if r: # Successsful response to DELETE is an empty string
                print(f"DELETE operation successful with {url2delete}")
                sucita_db[:] = [record for record in sucita_db if record["id"] != ID]
   
    return selected_item

@app.post("/files/", tags=["Manage Records"], deprecated=True)
async def post_image(image: bytes = File(...)):
    token_Firebase = FireCRUD.get_authToken()
    print(token_Firebase)

    url2file = 'https://firebasestorage.googleapis.com/v0/b/shiva-923e9.appspot.com/o/stash%2Frandom.png'
    headers = {"Content-Type": "image/png", "Authorization": "Bearer "+token_Firebase["idToken"]}

    try:
        r = requests.post(url2file, data=image, headers=headers)
        r.raise_for_status()
    except HTTPError as errHTTP:
        print(f"Got no successful response from Firebase API for storage. See: {errHTTP}")
    except Exception as err:
        print(f"Posted no image. See: {err}")
    
    response = r.json()

    return {"token": token_Firebase["idToken"], "fire": response}

@app.post("/uploadfile", response_model=Item_DB, tags=["Manage Records"], summary="Create a new record.")
async def upload_image(image: UploadFile = File(...), tag: List[str] = Query(..., example="king")):
    """
    Add a new record to the collection. You will need:

    - **image** - An image (local to client).
    - **document** -  An associated document, optional.
    - **tags** - Tags to identify the image and make it searchable.
    
    """
    try:
        token_Firebase = FireCRUD.get_authToken()
    except HTTPError as errHTTP:
        raise HTTPException(status_code=404, detail=f'Got no token from Firebase. See: {errHTTP}')
    except Exception as err:
        raise HTTPException(status_code=404, detail=f'Got no auth token. See: {err}')
    else:
        print(token_Firebase)
        if len(tag) > 1:
            tags = ",".join(tag)
        print(tags)
        url2fire = 'https://firebasestorage.googleapis.com/v0/b/shiva-923e9.appspot.com/o/stash%2F'
        url2file = url2fire + image.filename.replace(" ", "_")
        headers = {"Content-Type": image.content_type, "Authorization": "Bearer "+token_Firebase["idToken"]}

        try:
            r = requests.post(url2file, data=image.file.read(), headers=headers)
            r.raise_for_status()
        except HTTPError as errHTTP:
            raise HTTPException(status_code=404, detail=f'Firebase stored no image. See: {errHTTP}')
        except Exception as err:
            raise HTTPException(status_code=404, detail=f'Posted no image. See: {err}')
        else:           
            response = r.json()
            print(response)
            url2DB = url2file + '?alt=media&token=' + response["downloadTokens"]
            ret = Item(image=url2DB, tags=tags)
            ret = await add_item(ret)
    
    try:
        os.mkdir("images")
    except Exception as e:
        print(e)
    file_name = os.getcwd() + "/images/" + image.filename.replace(" ", "_")
    with open(file_name, "wb+") as f:
        image.file.seek(0)
        f.write(image.file.read())
        f.close()

    return ret

    