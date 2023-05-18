import os
import time
import logging
from datetime import datetime, timedelta
from typing import Optional
import re
from dotenv import load_dotenv
import aiomysql
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load sensitive data from environment variables
load_dotenv('./info.env')
DB_HOST = os.environ['DB_HOST']
DB_PORT = os.environ['DB_PORT']
DB_USER = os.environ['DB_USER']
DB_PASSWORD = os.environ['DB_PASSWORD']
DB_NAME = os.environ['DB_NAME']
SECRET_KEY = os.environ['SECRET_KEY']

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class UserIn(BaseModel):
    username: str
    password: str
    contact: str  # This will be the Jabber, Telegram, or Tox address

class UserOut(BaseModel):
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UpdatePasswordIn(BaseModel):
    username: str
    old_password: str
    new_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def get_db_pool():
    pool = await aiomysql.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        db=DB_NAME,
    )
    return pool

async def get_user(pool, username: str):
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute("SELECT *, TIMESTAMPDIFF(MINUTE, last_failed_login, NOW()) as failed_login_timeout FROM users WHERE username = %s", (username,))
            user = await cursor.fetchone()
            return user

async def authenticate_user(pool, username: str, password: str):
    user = await get_user(pool, username)
    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), pool=Depends(get_db_pool)):
    user = await get_user(pool, form_data.username)
    if not user or user['failed_login_attempts'] >= 5 and (user['failed_login_timeout'] is None or user['failed_login_timeout'] < 30):
        logger.warning(f"Unauthorized login attempt for user {form_data.username}")
        if user:
            async with pool.acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cursor:
                    await cursor.execute("UPDATE users SET last_failed_login = NOW() WHERE username = %s", (form_data.username,))
                    await conn.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password, or too many failed attempts",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(form_data.password, user['hashed_password']):
        logger.warning(f"Incorrect password for user {user['username']}")
        async with pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login = NOW() WHERE username = %s", (user['username'],))
                await conn.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            await cursor.execute("UPDATE users SET failed_login_attempts = 0 WHERE username = %s", (user['username'],))
            await conn.commit()
    logger.info(f"User {user['username']} logged in")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=1)
    access_token = create_access_token(
        data={"sub": user['username'], "type": "access"}, expires_delta=access_token_expires
    )
    refresh_token = create_access_token(
        data={"sub": user['username'], "type": "refresh"}, expires_delta=refresh_token_expires
    )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/register")
async def register(user_in: UserIn, pool=Depends(get_db_pool)):
    # Password validation
    password_regex = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
    if not re.match(password_regex, user_in.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password. It should contain at least one letter, one number, and be at least 8 characters long.",
        )
    hashed_password = get_password_hash(user_in.password)
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            try:
                await cursor.execute("SELECT * FROM users WHERE username = %s", (user_in.username,))
                user = await cursor.fetchone()
                if user:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Username already registered"
                    )
                await cursor.execute("INSERT INTO users (username, hashed_password, email) VALUES (%s, %s, %s)", (user_in.username, hashed_password, user_in.contact))
                await conn.commit()
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred while registering the user."
                )
    return {"message": "User created successfully"}


@app.put("/refresh-token")
async def refresh_token(refresh_token: str, pool=Depends(get_db_pool)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or payload.get("type") != "refresh":
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await get_user(pool, username)
    if user is None:
        raise credentials_exception
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username'], "type": "access"}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme), pool=Depends(get_db_pool)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(pool, token_data.username)
    if user is None:
        raise credentials_exception
    return user['username']

@app.get("/users/me", response_model=UserOut)
async def read_users_me(current_user: str = Depends(get_current_user)):
    return {"username": current_user}

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.put("/update-password")
async def update_password(update_password_in: UpdatePasswordIn, pool=Depends(get_db_pool)):
    # Verify old password
    user = await authenticate_user(pool, update_password_in.username, update_password_in.old_password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Validation for new_password
    password_regex = "^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$"
    if not re.match(password_regex, update_password_in.new_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid new password. It should contain at least one letter, one number, and be at least 8 characters long.",
        )
    new_hashed_password = get_password_hash(update_password_in.new_password)
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cursor:
            try:
                await cursor.execute("UPDATE users SET hashed_password = %s WHERE username = %s", (new_hashed_password, update_password_in.username))
                await conn.commit()
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An error occurred while updating the password."
                )
    return {"message": "Password updated successfully"}
