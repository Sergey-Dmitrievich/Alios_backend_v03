# app/schemas.py
from datetime import datetime
from typing import List, Optional
from fastapi import UploadFile
from pydantic import BaseModel

class UserBase(BaseModel):
    username: str
    phone_number: str  # Добавлено поле для номера телефона

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        from_attributes = True


class MessageBase(BaseModel):
    content: Optional[str] = None
    media_url: Optional[str] = None
    reply_to_id: Optional[int] = None
    read: bool = False

class MessageCreate(MessageBase):
    pass

class Message(MessageBase):
    id: int
    owner_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ReactionBase(BaseModel):
    message_id: int
    reaction_type: str

class ReactionCreate(ReactionBase):
    pass

class Reaction(ReactionBase):
    id: int
    user_id: int

    class Config:
        from_attributes = True


class GroupChatCreate(BaseModel):
    name: str
    description: str
    avatar: UploadFile 
    member_ids: List[int]  # Список ID участников
    is_private: bool  # Новое поле для указания типа чата

class ChannelCreate(BaseModel):
    name: str
    description: str
    avatar: UploadFile
    is_private: bool  # Новое поле для указания типа канала

class UserChannelGroupResponse(BaseModel):
    id: int  # ID созданного канала или группового чата
    name: str  # Имя канала или группового чата
    description: Optional[str] = None  # Описание
    is_private: bool  # Публичный или приватный
    avatar_url: Optional[str] = None  # Ссылка на аватар

class ChatChannelResponse(BaseModel):
    id: int
    name: str
    avatar_url: Optional[str]
    last_message_content: str
    last_message_owner: str
    last_message_created_at: datetime

    class Config:
        from_attributes = True