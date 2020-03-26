import uuid
from faker import Factory
from sqlalchemy import *
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Integer
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash

from config.config import *

engine = create_engine(SQLALCHEMY_DATABASE_URI)
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    public_id = Column(String(50), nullable=False, index=True)
    email = Column(String(50), nullable=False, index=True)
    password = Column(String(80), nullable=False)
    admin = Column(Boolean, unique=False, default=False)
    reset_token = Column(String())

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__, self.username)

if __name__ == 'config.create_database':
    Base.metadata.drop_all(bind=engine, tables=[User.__table__])
    Base.metadata.create_all(engine)

    faker = Factory.create()
    Session = sessionmaker(bind=engine)
    session = Session()
    faker_admin = [User(public_id=str(uuid.uuid4()), email='admin@admin.pl',
                       password=generate_password_hash('12345', method='sha256'), admin=True)]
    session.add_all(faker_admin)
    faker_users = [User(public_id=str(uuid.uuid4()), email=faker.email(),
                        password=generate_password_hash(faker.word(), method='sha256')) for i in range(10)]
    session.add_all(faker_users)
    session.commit()