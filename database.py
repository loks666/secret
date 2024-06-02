# database.py
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "mysql+pymysql://root:Lx284190056!@localhost/keys"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    public_key = Column(Text, nullable=False)


class Info(Base):
    __tablename__ = "info"
    id = Column(Integer, primary_key=True, index=True)
    sender_public_key = Column(Text, nullable=False)
    receiver_public_key = Column(Text, nullable=False)


Base.metadata.create_all(bind=engine)


def get_user_by_username(session, username):
    return session.query(User).filter(User.username == username).first()


def get_user_by_email(session, email):
    return session.query(User).filter(User.email == email).first()


def create_user(session, username, password, email, public_key):
    user = User(username=username, password=password, email=email, public_key=public_key)
    session.add(user)
    session.commit()
    return user


def create_info(session, sender_public_key, receiver_public_key):
    info = Info(sender_public_key=sender_public_key, receiver_public_key=receiver_public_key)
    session.add(info)
    session.commit()
    return info
