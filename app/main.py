# app/main.py
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, List, Union
import uuid
from fastapi import Body, FastAPI, Depends, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect, status, Security
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt

from .database import SessionLocal, engine, Base
from .models import Channel, ChannelMessage, ChannelSubscriber, GroupChat, GroupChatMember, Reaction, ReadStatus, User, Message
from .schemas import ChatChannelResponse, UserChannelGroupResponse, UserCreate, User, MessageCreate, Message
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
# Инициализация базы данных
Base.metadata.create_all(bind=engine)
# Папка для хранения медиафайлов
# Путь к директории для хранения медиа файлов


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],  # или укажите конкретные источники, например, ["http://localhost:4200"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MEDIA_DIR = "app/media"
AVATAR_UPLOAD_DIR = os.path.join(MEDIA_DIR, "avatars")

# Убедитесь, что директория для загрузки существует
os.makedirs(AVATAR_UPLOAD_DIR, exist_ok=True)

async def save_avatar(avatar: UploadFile) -> str:
    if not avatar.content_type in ["image/jpeg", "image/png", "image/gif"]:
        raise HTTPException(status_code=400, detail="Invalid file type. Only JPEG, PNG, and GIF are allowed.")

    unique_filename = f"{uuid.uuid4()}_{avatar.filename}"
    file_location = os.path.join(AVATAR_UPLOAD_DIR, unique_filename)

    with open(file_location, "wb") as file:
        file.write(await avatar.read())

    return f"/media/avatars/{unique_filename}"  # Возвращаем URL или путь к загруженному файлу


# Настройка приложения


# Генерация секретного ключа
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Настройка шифрования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Утилиты для работы с паролями и токенами
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Создание контекста для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Функция для получения текущего пользователя из токена
def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")  # Извлекаем ID пользователя
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    return user_id



db = SessionLocal()



# Зависимость для получения сессии
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Регистрируем пользователя
@app.post("/register")
async def register(
    username: str,
    phone_number: str,
    password: str,
    avatar: UploadFile = File(...),  # Поле для загрузки аватара
    db: Session = Depends(get_db)
    
):
    print(f"Received data: username={username}, phone_number={phone_number}, password={password}, avatar={avatar.filename if avatar else 'no file'}")
    
    # Проверка существования пользователя
    if db.query(User).filter(User.phone_number == phone_number).first():
        raise HTTPException(status_code=400, detail="Phone number already registered")

    # Хеширование пароля
    hashed_password = hash_password(password)

    # Сохранение аватара
    avatar_url = await save_avatar(avatar)

    # Создание нового пользователя
    new_user = User(username=username, phone_number=phone_number, password=hashed_password, avatar_url=avatar_url)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "username": new_user.username,
        "avatar_url": new_user.avatar_url
    }


@app.post("/token/")
def login(phone_number: str, password: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.phone_number == phone_number).first()  # Поиск по номеру телефона
    if not db_user or not verify_password(password, db_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect phone number or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user.id}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}
# Пример защищенного маршрута
@app.get("/users/me/", response_model=User)
def read_users_me(current_user: int = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current_user).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user




clients: Dict[int, List[WebSocket]] = {}  # user_id -> list of websockets

@app.websocket("/ws/chat/{user_id}")
async def chat_endpoint(websocket: WebSocket, user_id: int):
    if user_id not in clients:
        clients[user_id] = []
    
    await websocket.accept()
    clients[user_id].append(websocket)

    # Обновляем статус прочтения всех сообщений в чате для пользователя
    db = SessionLocal()
    messages = db.query(Message).all()  # Получите все сообщения (можно фильтровать по чату)

    for message in messages:
        # Проверяем, существует ли уже запись о прочтении для данного сообщения
        read_status = db.query(ReadStatus).filter(ReadStatus.message_id == message.id, ReadStatus.user_id == user_id).first()
        if not read_status:
            # Если записи нет, создаем новую
            new_read_status = ReadStatus(message_id=message.id, user_id=user_id)
            db.add(new_read_status)

    db.commit()  # Сохраняем изменения

    # Отправка истории сообщений при подключении
    await send_message_history(websocket)

    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")  # Определяем тип сообщения

            if message_type == "text":
                message_content = data.get("content")
                # Сохранение текстового сообщения в БД
                db_message = Message(content=message_content, owner_id=user_id)
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Отправка сообщения всем подключенным клиентам
                await broadcast_message(user_id, db_message, "text")

            elif message_type == "media":
                media_url = data.get("media_url")
                # Сохранение сообщения с медиафайлом
                db_message = Message(media_url=media_url, owner_id=user_id)
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Отправка сообщения всем подключенным клиентам
                await broadcast_message(user_id, db_message, "media")

            elif message_type == "edit":
                message_id = data.get("message_id")
                new_content = data.get("content")
                # Поиск сообщения и редактирование его
                db_message = db.query(Message).filter(Message.id == message_id).first()
                if db_message:
                    db_message.content = new_content
                    db_message.updated_at = datetime.utcnow()  # Обновляем время редактирования
                    db.commit()

                    # Отправка обновленного сообщения всем подключенным клиентам
                    await broadcast_edit(user_id, message_id, new_content, db_message.updated_at)

    except WebSocketDisconnect:
        clients[user_id].remove(websocket)
        if not clients[user_id]:
            del clients[user_id]  # Удаляем пользователя, если больше нет клиентов


async def send_message_history(websocket: WebSocket):
    db = SessionLocal()
    messages = db.query(Message).all()  # Получите все сообщения (можно фильтровать по чату)
    
    await websocket.send_json({
        "type": "history",
        "messages": [
            {
                "id": message.id,
                "content": message.content,
                "media_url": message.media_url,
                "owner_id": message.owner_id,
                "created_at": message.created_at,
                "updated_at": message.updated_at,
                "read": message.read
            } for message in messages
        ]
    })


async def broadcast_message(user_id: int, db_message: Message, message_type: str):
    for client in clients[user_id]:
        await client.send_json({
            "type": message_type,
            "content": db_message.content,
            "media_url": db_message.media_url,
            "message_id": db_message.id,
            "owner_id": user_id,
            "read": db_message.read,
            "created_at": db_message.created_at
        })
        

async def broadcast_edit(user_id: int, message_id: int, new_content: str, updated_at: datetime):
    for client in clients[user_id]:
        await client.send_json({
            "type": "edit",
            "message_id": message_id,
            "new_content": new_content,
            "owner_id": user_id,
            "updated_at": updated_at
        })


@app.post("/group_chat/create", response_model=UserChannelGroupResponse)
async def create_group_chat(
    name: str,
    description: str,
    avatar: UploadFile = File(...),
    member_ids: List[int] = Body(...),  # Список ID участников
    is_private: bool = Body(...),  # Параметр для определения типа чата
    user_id: int = Depends(get_current_user),  # Используем ID из токена
    db: Session = Depends(get_db)  # Получаем сессию БД
):
    # Проверяем, что имя чата не пустое
    if not name:
        raise HTTPException(status_code=400, detail="Chat name cannot be empty")

    # Сохраняем аватар
    avatar_url = await save_avatar(avatar)

    # Проверка на существование чата с таким названием
    existing_chat = db.query(GroupChat).filter(GroupChat.name == name).first()
    if existing_chat:
        raise HTTPException(status_code=400, detail="Group chat with this name already exists.")

    # Создаем новый групповой чат
    new_chat = GroupChat(
        name=name,
        description=description,
        avatar_url=avatar_url,
        is_private=is_private  # Обновляем поле для типа чата
    )
    db.add(new_chat)
    db.commit()
    db.refresh(new_chat)

    # Добавляем создателя чата как администратора
    chat_member = GroupChatMember(chat_id=new_chat.id, user_id=user_id, role='admin')
    db.add(chat_member)

    # Добавляем других участников, проверяя их существование
    for member_id in member_ids:
        # Проверяем, существует ли пользователь с данным ID
        if not db.query(User).filter(User.id == member_id).first():
            raise HTTPException(status_code=404, detail=f"User with ID {member_id} not found")

        chat_member = GroupChatMember(chat_id=new_chat.id, user_id=member_id, role='member')
        db.add(chat_member)

    db.commit()  # Сохраняем изменения

    return {
        "message": "Group chat created successfully",
        "chat_id": new_chat.id,
        "name": new_chat.name,
        "description": new_chat.description,
        "avatar_url": new_chat.avatar_url,
        "members": member_ids
    }


@app.post("/channel/create", response_model=UserChannelGroupResponse)
async def create_channel(
    name: str,
    description: str,
    avatar: UploadFile = File(...),
    is_private: bool = Body(...),  # Новое поле для определения типа канала
    user_id: int = Depends(get_current_user),  # Используем ID из токена
    db: Session = Depends(get_db)  # Получаем сессию БД
):
    # Проверяем, что имя канала не пустое
    if not name:
        raise HTTPException(status_code=400, detail="Channel name cannot be empty")

    # Сохраняем аватар
    avatar_url = await save_avatar(avatar)

    # Проверка на существование канала с таким названием
    existing_channel = db.query(Channel).filter(Channel.name == name).first()
    if existing_channel:
        raise HTTPException(status_code=400, detail="Channel with this name already exists.")

    # Создаем новый канал
    new_channel = Channel(
        name=name,
        description=description,
        avatar_url=avatar_url,
        is_private=is_private  # Устанавливаем тип канала
    )
    db.add(new_channel)
    db.commit()
    db.refresh(new_channel)

    # Добавляем создателя канала как подписчика
    channel_subscriber = ChannelSubscriber(channel_id=new_channel.id, user_id=user_id)
    db.add(channel_subscriber)
    db.commit()

    return {
        "message": "Channel created successfully",
        "channel_id": new_channel.id,
        "name": new_channel.name,
        "description": new_channel.description,
        "avatar_url": new_channel.avatar_url,
        "visibility": "public" if not new_channel.is_private else "private"  # Возвращаем тип канала
    }




@app.post("/channel/subscribe/{channel_id}")
async def subscribe_to_channel(
    channel_id: int,
    user_id: int = Depends(get_current_user),  # Используем ID из токена
    db: Session = Depends(SessionLocal)  # Получаем сессию БД
):
    channel = db.query(Channel).filter(Channel.id == channel_id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")

    # Проверяем, подписан ли пользователь уже на канал
    if db.query(ChannelSubscriber).filter(ChannelSubscriber.channel_id == channel_id, ChannelSubscriber.user_id == user_id).first():
        raise HTTPException(status_code=400, detail="Already subscribed to this channel")

    # Добавляем подписчика
    new_subscriber = ChannelSubscriber(channel_id=channel_id, user_id=user_id)
    db.add(new_subscriber)
    db.commit()

    return {"message": "Successfully subscribed to the channel"}

clients: Dict[int, List[WebSocket]] = {}  # group_id -> list of websockets


@app.websocket("/ws/channel/{channel_id}")
async def channel_chat_endpoint(websocket: WebSocket, channel_id: int, user_id: int = Depends(get_current_user)):
    if channel_id not in clients:
        clients[channel_id] = []

    await websocket.accept()
    clients[channel_id].append(websocket)

    # Отправка истории сообщений при подключении
    await send_channel_message_history(websocket, channel_id)

    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")  # Определяем тип сообщения

            if message_type == "text":
                message_content = data.get("content")
                # Сохранение текстового сообщения в БД
                db_message = Message(content=message_content, owner_id=user_id, channel_id=channel_id)
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Отправка сообщения всем подключенным клиентам
                await broadcast_channel_message(channel_id, db_message)

            elif message_type == "media":
                media_file = data.get("file")  # Получаем файл из данных
                media_url = await save_media_file(media_file)  # Сохраняем файл и получаем URL

                # Сохранение медиа-сообщения в БД
                db_message = Message(content=media_url, owner_id=user_id, channel_id=channel_id, is_media=True)
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Отправка медиа-сообщения всем подключенным клиентам
                await broadcast_channel_media_message(channel_id, db_message)

            elif message_type == "edit":
                message_id = data.get("message_id")
                new_content = data.get("content")
                # Поиск сообщения и редактирование его
                db_message = db.query(Message).filter(Message.id == message_id, Message.channel_id == channel_id).first()
                if db_message:
                    db_message.content = new_content
                    db_message.updated_at = datetime.utcnow()  # Обновляем время редактирования
                    db.commit()

                    # Отправка обновленного сообщения всем подключенным клиентам
                    await broadcast_channel_edit(channel_id, message_id, new_content)

            elif message_type == "delete":
                message_id = data.get("message_id")
                # Удаление сообщения
                db_message = db.query(Message).filter(Message.id == message_id, Message.channel_id == channel_id).first()
                if db_message:
                    db.delete(db_message)
                    db.commit()
                    # Уведомление всех клиентов о том, что сообщение удалено
                    await broadcast_channel_delete(channel_id, message_id)

            elif message_type == "reaction":
                message_id = data.get("message_id")
                reaction_type = data.get("reaction")

                # Логика для добавления или обновления реакции
                existing_reaction = db.query(Reaction).filter(
                    Reaction.message_id == message_id,
                    Reaction.user_id == user_id
                ).first()

                if existing_reaction:
                    existing_reaction.reaction_type = reaction_type
                else:
                    new_reaction = Reaction(message_id=message_id, user_id=user_id, reaction_type=reaction_type)
                    db.add(new_reaction)

                db.commit()
                await broadcast_channel_reaction(channel_id, message_id, user_id, reaction_type)

    except WebSocketDisconnect:
        clients[channel_id].remove(websocket)
        if not clients[channel_id]:
            del clients[channel_id]  # Удаляем канал, если больше нет клиентов


async def send_channel_message_history(websocket: WebSocket, channel_id: int):
    db = SessionLocal()
    messages = db.query(Message).filter(Message.channel_id == channel_id).all()  # Получаем все сообщения для канала
    
    await websocket.send_json({
        "type": "history",
        "messages": [
            {
                "id": message.id,
                "content": message.content,
                "owner_id": message.owner_id,
                "created_at": message.created_at,
                "updated_at": message.updated_at,
                "is_media": message.is_media
            } for message in messages
        ]
    })


async def broadcast_channel_message(channel_id: int, db_message: Message):
    for client in clients.get(channel_id, []):
        await client.send_json({
            "type": "text",
            "content": db_message.content,
            "message_id": db_message.id,
            "owner_id": db_message.owner_id,
            "created_at": db_message.created_at,
            "is_media": False
        })


async def broadcast_channel_media_message(channel_id: int, db_message: Message):
    for client in clients.get(channel_id, []):
        await client.send_json({
            "type": "media",
            "media_url": db_message.content,
            "message_id": db_message.id,
            "owner_id": db_message.owner_id,
            "created_at": db_message.created_at,
            "is_media": True
        })


async def broadcast_channel_edit(channel_id: int, message_id: int, new_content: str):
    for client in clients.get(channel_id, []):
        await client.send_json({
            "type": "edit",
            "message_id": message_id,
            "new_content": new_content
        })


async def broadcast_channel_delete(channel_id: int, message_id: int):
    for client in clients.get(channel_id, []):
        await client.send_json({
            "type": "delete",
            "message_id": message_id
        })


async def broadcast_channel_reaction(channel_id: int, message_id: int, user_id: int, reaction: str):
    for client in clients.get(channel_id, []):
        await client.send_json({
            "type": "reaction",
            "message_id": message_id,
            "user_id": user_id,
            "reaction": reaction
        })


async def save_media_file(file: UploadFile) -> str:
    unique_filename = f"{uuid.uuid4()}_{file.filename}"
    file_location = os.path.join(MEDIA_DIR, unique_filename)

    with open(file_location, "wb") as f:
        f.write(await file.read())

    return f"/media/messages/{unique_filename}"



@app.websocket("/ws/group_chat/{group_id}")
async def group_chat_endpoint(websocket: WebSocket, group_id: int, user_id: int = Depends(get_current_user)):
    if group_id not in clients:
        clients[group_id] = []
    
    await websocket.accept()
    clients[group_id].append(websocket)

    # Отправка истории сообщений при подключении
    await send_group_message_history(websocket, group_id)

    # Обновляем статус прочтения всех сообщений в чате для пользователя
    
    messages = db.query(Message).filter(Message.group_id == group_id).all()

    for message in messages:
        # Помечаем все сообщения как прочитанные для пользователя
        read_status = db.query(ReadStatus).filter(ReadStatus.message_id == message.id, ReadStatus.user_id == user_id).first()
        if not read_status:
            new_read_status = ReadStatus(message_id=message.id, user_id=user_id)
            db.add(new_read_status)

    db.commit()

    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")  # Определяем тип сообщения

            if message_type == "text":
                message_content = data.get("content")
                # Сохранение текстового сообщения в БД
                db_message = Message(content=message_content, owner_id=user_id, group_id=group_id)
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Отправка сообщения всем подключенным клиентам
                await broadcast_group_message(group_id, db_message)

            elif message_type == "media":
                media_file = data.get("file")  # Получаем файл из данных
                media_url = await save_media_file(media_file)  # Сохраняем файл и получаем URL

                # Сохранение медиа-сообщения в БД
                db_message = Message(content=media_url, owner_id=user_id, group_id=group_id, is_media=True)
                db.add(db_message)
                db.commit()
                db.refresh(db_message)

                # Отправка медиа-сообщения всем подключенным клиентам
                await broadcast_group_media_message(group_id, db_message)

            elif message_type == "edit":
                message_id = data.get("message_id")
                new_content = data.get("content")
                # Поиск сообщения и редактирование его
                db_message = db.query(Message).filter(Message.id == message_id, Message.group_id == group_id).first()
                if db_message:
                    db_message.content = new_content
                    db_message.updated_at = datetime.utcnow()  # Обновляем время редактирования
                    db.commit()

                    # Отправка обновленного сообщения всем подключенным клиентам
                    await broadcast_group_edit(group_id, message_id, new_content)

            elif message_type == "delete":
                message_id = data.get("message_id")
                # Удаление сообщения
                db_message = db.query(Message).filter(Message.id == message_id, Message.group_id == group_id).first()
                if db_message:
                    db.delete(db_message)
                    db.commit()
                    # Уведомление всех клиентов о том, что сообщение удалено
                    await broadcast_group_delete(group_id, message_id)

            elif message_type == "reaction":
                message_id = data.get("message_id")
                reaction_type = data.get("reaction")

                # Логика для добавления или обновления реакции
                existing_reaction = db.query(Reaction).filter(
                    Reaction.message_id == message_id,
                    Reaction.user_id == user_id
                ).first()

                if existing_reaction:
                    existing_reaction.reaction_type = reaction_type
                else:
                    new_reaction = Reaction(message_id=message_id, user_id=user_id, reaction_type=reaction_type)
                    db.add(new_reaction)

                db.commit()
                await broadcast_group_reaction(group_id, message_id, user_id, reaction_type)

    except WebSocketDisconnect:
        clients[group_id].remove(websocket)
        if not clients[group_id]:
            del clients[group_id]  # Удаляем группу, если больше нет клиентов


async def broadcast_group_reaction(group_id: int, message_id: int, user_id: int, reaction: str):
    for client in clients.get(group_id, []):
        await client.send_json({
            "type": "reaction",
            "message_id": message_id,
            "user_id": user_id,
            "reaction": reaction
        })


async def save_media_file(file: UploadFile) -> str:
    unique_filename = f"{uuid.uuid4()}_{file.filename}"
    file_location = os.path.join(MEDIA_DIR, unique_filename)

    with open(file_location, "wb") as f:
        f.write(await file.read())

    return f"/media/messages/{unique_filename}"


async def send_group_message_history(websocket: WebSocket, group_id: int):
    db = SessionLocal()
    messages = db.query(Message).filter(Message.group_id == group_id).all()  # Получаем все сообщения для группы
    
    await websocket.send_json({
        "type": "history",
        "messages": [
            {
                "id": message.id,
                "content": message.content,
                "owner_id": message.owner_id,
                "created_at": message.created_at,
                "updated_at": message.updated_at,
                "is_media": message.is_media
            } for message in messages
        ]
    })


async def broadcast_group_message(group_id: int, db_message: Message):
    for client in clients.get(group_id, []):
        await client.send_json({
            "type": "text",
            "content": db_message.content,
            "message_id": db_message.id,
            "owner_id": db_message.owner_id,
            "created_at": db_message.created_at,
            "is_media": False
        })


async def broadcast_group_media_message(group_id: int, db_message: Message):
    for client in clients.get(group_id, []):
        await client.send_json({
            "type": "media",
            "media_url": db_message.content,
            "message_id": db_message.id,
            "owner_id": db_message.owner_id,
            "created_at": db_message.created_at,
            "is_media": True
        })


async def broadcast_group_edit(group_id: int, message_id: int, new_content: str):
    for client in clients.get(group_id, []):
        await client.send_json({
            "type": "edit",
            "message_id": message_id,
            "new_content": new_content
        })


async def broadcast_group_delete(group_id: int, message_id: int):
    for client in clients.get(group_id, []):
        await client.send_json({
            "type": "delete",
            "message_id": message_id
        })



@app.get("/network/entities", response_model=List[Union[UserChannelGroupResponse]])
async def get_all_entities(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_id = current_user.id  # Извлечение user_id из токена

    # Получение пользователей
    users = db.query(User).all()

    # Получение каналов
    channels = db.query(Channel).all()

    # Получение групповых чатов и участников
    group_chats = db.query(GroupChat).all()

    results = []

    # Обработка пользователей
    for user in users:
        online_status = "online" if user.is_online else "offline"  # Предполагается, что есть поле is_online
        results.append(UserChannelGroupResponse(
            id=user.id,
            name=user.username,
            avatar_url=user.avatar_url,
            type="user",
            status=online_status
        ))

    # Обработка каналов
    for channel in channels:
        visibility = "публичный" if channel.is_public else "закрытый"  # Предполагается, что есть поле is_public
        results.append(UserChannelGroupResponse(
            id=channel.id,
            name=channel.name,
            avatar_url=channel.avatar_url,
            type="channel",
            visibility=visibility
        ))

    # Обработка групповых чатов
    for chat in group_chats:
        participant_count = db.query(GroupChatMember).filter(GroupChatMember.group_chat_id == chat.id).count()
        results.append(UserChannelGroupResponse(
            id=chat.id,
            name=chat.name,
            avatar_url=chat.avatar_url,
            type="group_chat",
            participant_count=participant_count
        ))

    return results

