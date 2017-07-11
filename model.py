"""
   Copyright 2017 Fastboot Mobile, LLC.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine.reflection import Inspector
from sqlalchemy.orm import sessionmaker, relationship
from nacl.public import PrivateKey
import nacl.signing
import nacl.encoding

db = create_engine('sqlite:///mydatabase.sqlite')

echo = False
Base = declarative_base()
DBSession = sessionmaker()
DBSession.bind = db
session = DBSession()
Base.metadata.bind = db
DBSession = sessionmaker(bind=db)
session = DBSession()


class Application(Base):

    __tablename__ = "application"

    id = Column("id", Integer, primary_key=True)
    desc = Column('app_desc', String(32), nullable=False)
    api_key = Column('api_key', String(64), nullable=False)  # api_key (used for signature validation)
    application_key = Column('app_key', String(64), nullable=False)  # app_key (used for message route)

    def __str__(self):
        return self.desc


class Device(Base):

    __tablename__ = "device"

    id = Column("id", Integer, primary_key=True)
    public_id = Column('public_id', String(64), nullable=False)  # Public ID of device
    last_seen = Column('last_seen', DateTime, nullable=False)  # Last seen time of this device / install

    def __str__(self):
        return self.public_id


class Installs(Base):

    __tablename__ = "installs"

    id = Column(Integer, primary_key=True)
    install_id = Column('install', String(129), nullable=False)  # Per install public key (used for message route)
    device_id = Column('device', Integer, ForeignKey(Device.id), nullable=False)  # Device id
    device = relationship('Device') # relationship back to device
    app_id = Column('app_id', Integer, ForeignKey(Application.id), nullable=False)  # Foreign key to application
    app = relationship('Application')  # Track what application this install is for
    last_seen = Column('last_seen', DateTime, nullable=False)  # Last seen time of this device / install

    def __str__(self):
        return self.install_id + ":" + self.device_id


def setupDb():
    Base.metadata.create_all(db)

    print("Setting up new application")

    api_key = nacl.signing.SigningKey.generate()
    app_key = PrivateKey.generate()

    print("PRIVATE API / SIGN KEY (KEEP SAFE)")
    print(api_key.encode(nacl.encoding.HexEncoder).decode())

    print("\n\n")

    print("PRIVATE APP / ENCRYPT (KEEP SAFE)")
    print(app_key.encode(nacl.encoding.HexEncoder).decode())
    print("PUBLIC APP / ENCRYPT (ADD TO APP)")
    print(app_key.public_key.encode(nacl.encoding.HexEncoder).decode())
    print("\n\n")

    app_fast_guard = Application()
    app_fast_guard.api_key = api_key.verify_key.encode(nacl.encoding.HexEncoder).decode()
    app_fast_guard.application_key = app_key.public_key.encode(nacl.encoding.HexEncoder).decode()
    app_fast_guard.desc = "My Push Application"

    session.add(app_fast_guard)
    session.commit()

inspector = Inspector.from_engine(db)
names = inspector.get_table_names()

# If no tables exist, setup the db
if len(names) < 1:
    setupDb()


