from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Form, File, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from database import get_db
from database.models.accounts import UserModel, UserProfileModel, UserGroupEnum, UserGroupModel
from schemas.profiles import ProfileResponseSchema
from storages import S3StorageInterface
from security.interfaces import JWTAuthManagerInterface
from config import get_s3_storage_client, get_jwt_auth_manager
from security.http import get_token
from validation import validate_name, validate_birth_date, validate_image, validate_gender, validate_info
from exceptions import InvalidTokenError, TokenExpiredError


router = APIRouter()


async def authorize_user(
        token: str,
        db: AsyncSession,
        user_id: int,
        jwt_manager: JWTAuthManagerInterface
):
    try:
        payload = jwt_manager.decode_access_token(token)
        token_user_id = payload.get("user_id")
        if not token_user_id or not isinstance(token_user_id, int):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing user_id in token."
            )
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
    if user_id != token_user_id:
        result_user_group = await db.execute(
            select(UserGroupModel).join(UserModel).where(UserModel.id == token_user_id)
        )
        user_group = result_user_group.scalar_one_or_none()
        if not user_group or user_group.name == UserGroupEnum.USER:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have permission to edit this profile."
            )


def validate_profile_data(
        first_name,
        last_name,
        gender,
        date_of_birth,
        info
):
    try:
        first_name = validate_name(first_name)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    try:
        last_name = validate_name(last_name)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    if not info.strip():
        raise HTTPException(status_code=422, detail="Info field cannot be empty or contain only spaces.")
    validated_data = {
        "first_name": first_name.lower() if first_name else "",
        "last_name": last_name.lower() if last_name else "",
        "info": info
    }
    if gender is not None:
        try:
            validated_data["gender"] = validate_gender(gender)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    else:
        validated_data["gender"] = None
    if date_of_birth is not None:
        try:
            validated_data["date_of_birth"] = validate_birth_date(date_of_birth)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    else:
        validated_data["date_of_birth"] = None
    return validated_data


async def create_profile(
        db: AsyncSession,
        s3_client: S3StorageInterface,
        user_id: int,
        avatar: Optional[UploadFile],
        **data
):
    existing = await db.execute(select(UserProfileModel).where(UserProfileModel.user_id == user_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User already has a profile.")
    profile = UserProfileModel(user_id=user_id, **data)
    if avatar:
        try:
            validate_image(avatar)
            avatar_bytes = await avatar.read()
            ext = avatar.filename.split(".")[-1] if "." in avatar.filename else "jpg"
            avatar_key = f"avatars/{user_id}_avatar.{ext}"
            await s3_client.upload_file(avatar_key, avatar_bytes)
            profile.avatar = avatar_key
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to upload avatar. Please try again later.")
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    avatar_url = await s3_client.get_file_url(profile.avatar) if profile.avatar else None
    response = ProfileResponseSchema.model_validate(profile)
    response.avatar = avatar_url
    return response


@router.post("/users/{user_id}/profile/", response_model=ProfileResponseSchema, status_code=status.HTTP_201_CREATED)
async def create_user_profile(
        user_id: int,
        first_name: str = Form(...),
        last_name: str = Form(...),
        gender: Optional[str] = Form(None),
        date_of_birth: Optional[date] = Form(None),
        info: str = Form(...),
        avatar: Optional[UploadFile] = File(None),
        db: AsyncSession = Depends(get_db),
        s3_client: S3StorageInterface = Depends(get_s3_storage_client),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        token: str = Depends(get_token),
):
    await authorize_user(token, db, user_id, jwt_manager)

    validated_data = validate_profile_data(
        first_name,
        last_name,
        gender,
        date_of_birth,
        info
    )

    if avatar:
        try:
            validate_image(avatar)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or not active.")

    profile = await create_profile(db, s3_client, user_id, avatar, **validated_data)
    return profile
