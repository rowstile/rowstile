"""The conformance app's tables: projects with members, notes in them, a service that reads projects, an
inbox people can write to but only the recipient reads, and folders inside folders."""

from django.db import models


class User(models.Model):
    id = models.BigIntegerField(primary_key=True)
    name = models.TextField()

    class Meta:
        db_table = "users"


class Service(models.Model):
    id = models.BigIntegerField(primary_key=True)
    name = models.TextField()

    class Meta:
        db_table = "services"


class Project(models.Model):
    id = models.BigIntegerField(primary_key=True)
    owner = models.ForeignKey(User, models.CASCADE, related_name="+")
    name = models.TextField()
    public = models.BooleanField(default=False)

    class Meta:
        db_table = "projects"


class Member(models.Model):
    pk = models.CompositePrimaryKey("project", "user")
    project = models.ForeignKey(Project, models.CASCADE, related_name="+")
    user = models.ForeignKey(User, models.CASCADE, related_name="+")

    class Meta:
        db_table = "members"


class ProjectService(models.Model):
    pk = models.CompositePrimaryKey("project", "service")
    project = models.ForeignKey(Project, models.CASCADE, related_name="+")
    service = models.ForeignKey(Service, models.CASCADE, related_name="+")

    class Meta:
        db_table = "project_services"


class Note(models.Model):
    id = models.BigAutoField(primary_key=True)
    project = models.ForeignKey(Project, models.CASCADE, related_name="+")
    author = models.ForeignKey(User, models.CASCADE, related_name="+")
    body = models.TextField()

    class Meta:
        db_table = "notes"


class Message(models.Model):
    id = models.BigAutoField(primary_key=True)
    sender = models.ForeignKey(User, models.CASCADE, related_name="+")
    recipient = models.ForeignKey(User, models.CASCADE, related_name="+")
    body = models.TextField()

    class Meta:
        db_table = "inbox"


class Folder(models.Model):
    id = models.BigIntegerField(primary_key=True)
    parent = models.ForeignKey("self", models.CASCADE, null=True, related_name="+")
    owner = models.ForeignKey(User, models.CASCADE, related_name="+")
    name = models.TextField()

    class Meta:
        db_table = "folders"
