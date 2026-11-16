"""The conformance app's tables: projects with members, notes in them, a service that reads projects, an
inbox people can write to but only the recipient reads, and folders inside folders."""

from typing import Any

from sqlalchemy import BigInteger, Boolean, ForeignKey, MetaData, Text, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData(schema="app")


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    # what an identity provider says of a user (SCIM): app.scim_user writes them
    email: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, server_default=true())
    scim: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column(Text)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("app.users.id"))
    name: Mapped[str] = mapped_column(Text)
    public: Mapped[bool] = mapped_column(Boolean, default=False)


class Member(Base):
    __tablename__ = "members"
    project_id: Mapped[int] = mapped_column(ForeignKey("app.projects.id"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("app.users.id"), primary_key=True, index=True)


class ProjectService(Base):
    __tablename__ = "project_services"
    project_id: Mapped[int] = mapped_column(ForeignKey("app.projects.id"), primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("app.services.id"), primary_key=True, index=True)


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("app.projects.id"), index=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("app.users.id"), index=True)
    body: Mapped[str] = mapped_column(Text)


class Message(Base):
    __tablename__ = "inbox"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("app.users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("app.users.id"), index=True)
    body: Mapped[str] = mapped_column(Text)


class Folder(Base):
    __tablename__ = "folders"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("app.folders.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("app.users.id"), index=True)
    name: Mapped[str] = mapped_column(Text)
