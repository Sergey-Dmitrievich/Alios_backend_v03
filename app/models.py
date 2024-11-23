# app/models.py
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    phone_number = Column(String, unique=True, index=True)  # Добавлено поле для номера телефона
    password = Column(String)  # Хранение пароля в хэшированном виде
    avatar_url = Column(String, nullable=True)  # Поле для хранения URL аватара

    messages = relationship("Message", back_populates="owner")

class Message(Base):
    __tablename__ = 'messages'
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String, nullable=True)  # Текст сообщения
    media_url = Column(String, nullable=True)  # Ссылка на медиафайл
    reply_to_id = Column(Integer, ForeignKey('messages.id'), nullable=True)  # ID сообщения, на которое отвечает
    read = Column(Boolean, default=False)  # Статус прочтения
    owner_id = Column(Integer, ForeignKey('users.id'))  # ID пользователя
    created_at = Column(DateTime, default=datetime.utcnow)  # Дата и время создания сообщения
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Дата и время последнего обновления

    owner = relationship("User")
    replies = relationship("Message", back_populates="reply", remote_side=[id])  # Ответы на сообщения
    reactions = relationship("Reaction", back_populates="message")

class ReadStatus(Base):
    __tablename__ = 'read_status'
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey('messages.id'))
    user_id = Column(Integer, ForeignKey('users.id'))

    message = relationship("MessageModel")
    user = relationship("User")

class GroupChat(Base):
    __tablename__ = 'group_chats'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # Имя чата
    description = Column(String, nullable=True)  # Описание чата
    avatar_url = Column(String, nullable=True)  # Ссылка на аватар чата
    is_private = Column(Boolean, default=False)  # Поле для хранения типа чата

    members = relationship("GroupChatMember", back_populates="chat")

class GroupChatMember(Base):
    __tablename__ = 'group_chat_members'
    
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey('group_chats.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    role = Column(String, default='member')  # Роль: admin, moderator, member

    chat = relationship("GroupChat", back_populates="members")
    user = relationship("User")

class Channel(Base):
    __tablename__ = 'channels'
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # Имя канала
    description = Column(String, nullable=True)  # Описание канала
    avatar_url = Column(String, nullable=True)  # Ссылка на аватар канала
    is_private = Column(Boolean, default=False)  # Поле для хранения типа канала


    subscribers = relationship("ChannelSubscriber", back_populates="channel")
    messages = relationship("ChannelMessage", back_populates="channel")

class ChannelSubscriber(Base):
    __tablename__ = 'channel_subscribers'
    
    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey('channels.id'))
    user_id = Column(Integer, ForeignKey('users.id'))

    channel = relationship("Channel", back_populates="subscribers")
    user = relationship("User")

class ChannelMessage(Base):
    __tablename__ = 'channel_messages'
    
    id = Column(Integer, primary_key=True, index=True)
    channel_id = Column(Integer, ForeignKey('channels.id'))
    content = Column(String, nullable=False)  # Содержимое сообщения
    created_at = Column(DateTime, default=datetime.utcnow)

    channel = relationship("Channel", back_populates="messages")

class Reaction(Base):
    __tablename__ = 'reactions'
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(Integer, ForeignKey('messages.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    reaction_type = Column(String, nullable=False)  # Тип реакции (например, like, love)

    message = relationship("Message", back_populates="reactions")
    user = relationship("User")


