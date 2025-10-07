from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Form, File, UploadFile, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from database import get_db
from database.models.accounts import UserModel, UserProfileModel, UserGroupEnum
from schemas.profiles import ProfileResponseSchema
from storages import S3StorageInterface
from security.interfaces import JWTAuthManagerInterface
from config import get_s3_storage_client, get_jwt_auth_manager
from validation import validate_name, validate_birth_date, validate_image, validate_gender
from exceptions import InvalidTokenError, TokenExpiredError


router = APIRouter()


async def authorize_user(request, jwt_manager, db, user_id):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Authorization header is missing")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'"
        )
    token = auth_header.split(" ")[1]

    try:
        payload = jwt_manager.decode_access_token(token)
    except (InvalidTokenError, TokenExpiredError):
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    current_user_id = payload.get("user_id")
    if current_user_id is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    stmt = select(UserModel).where(UserModel.id == current_user_id).options(selectinload(UserModel.group))
    current_user = (await db.execute(stmt)).scalar_one_or_none()
    if not current_user or not current_user.is_active:
        raise HTTPException(status_code=401, detail="User not found or not active.")

    if current_user_id != user_id and (not current_user.group or current_user.group.name != UserGroupEnum.ADMIN):
        raise HTTPException(status_code=403, detail="You don't have permission to edit this profile.")

    return current_user


def validate_profile_data(first_name, last_name, gender, date_of_birth, info):
    try:
        first_name = validate_name(first_name)
        last_name = validate_name(last_name)
        if not first_name or not last_name:
            raise ValueError("Invalid first or last name")

        first_name = first_name.lower()
        last_name = last_name.lower()

        if gender:
            gender = validate_gender(gender)
        if date_of_birth:
            date_of_birth = validate_birth_date(date_of_birth)
        if not info.strip():
            raise ValueError("Info field cannot be empty or contain only spaces.")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


async def create_profile(db, s3_client, user_id, avatar, **data):
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
            raise HTTPException(status_code=500, detail="Failed to upload avatar.")
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    avatar_url = await s3_client.get_file_url(profile.avatar) if profile.avatar else None
    response = ProfileResponseSchema.from_orm(profile)
    response.avatar = avatar_url
    return response


@router.post(
    "/users/{user_id}/profile/",
    response_model=ProfileResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def create_user_profile(
    user_id: int,
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    gender: Optional[str] = Form(None),
    date_of_birth: Optional[date] = Form(None),
    info: str = Form(...),
    avatar: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    s3_client: S3StorageInterface = Depends(get_s3_storage_client),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    await authorize_user(
        request,
        jwt_manager,
        db,
        user_id
    )
    validated_data = validate_profile_data(
        first_name,
        last_name,
        gender,
        date_of_birth,
        info
    )
    profile = await create_profile(
        db,
        s3_client,
        user_id,
        avatar,
        **validated_data
    )
    return profile
