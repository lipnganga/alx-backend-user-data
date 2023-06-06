#!/usr/bin/env python3
# create a user model

from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class User(Base):
    """summary: create a user model"""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        return "<User: %s>" % self.username
