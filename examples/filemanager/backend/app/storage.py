"""File contents in RustFS (any S3-compatible store). The backend writes and deletes objects; browsers
download through links signed only after the file's row was read through row-level security.

A browser uploads to a place of its own (uploads/<key>), never to the object a file points at: the backend
moves the bytes there when the upload is confirmed (accept), and reads their size then. So the signed upload
link, which goes on working for a few minutes, can't change a confirmed file or its size afterwards."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import BinaryIO
from urllib.parse import quote

import boto3
from botocore.client import Config

from .config import Settings


class Storage:
    def __init__(self, s: Settings) -> None:
        common = {
            "aws_access_key_id": s.s3_access_key,
            "aws_secret_access_key": s.s3_secret_key,
            "region_name": s.s3_region,
            "config": Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        }
        self.s3 = boto3.client("s3", endpoint_url=s.s3_endpoint, **common)
        self.public = boto3.client("s3", endpoint_url=s.s3_public_endpoint, **common)
        self.bucket, self.link_seconds, self.origins = s.s3_bucket, s.link_minutes * 60, list(s.web_origins)

    def ensure_bucket(self) -> None:
        names = {b["Name"] for b in self.s3.list_buckets().get("Buckets", [])}
        if self.bucket not in names:
            self.s3.create_bucket(Bucket=self.bucket)
        # the web app uploads straight to the bucket with signed links
        self.s3.put_bucket_cors(
            Bucket=self.bucket,
            CORSConfiguration={
                "CORSRules": [
                    {
                        "AllowedOrigins": self.origins,
                        "AllowedMethods": ["PUT", "GET"],
                        "AllowedHeaders": ["*"],
                        "MaxAgeSeconds": 3600,
                    }
                ]
            },
        )

    def put(self, key: str, fileobj: BinaryIO, content_type: str) -> None:
        self.s3.upload_fileobj(fileobj, self.bucket, key, ExtraArgs={"ContentType": content_type})

    def delete(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=key)

    def download_link(self, key: str, filename: str) -> str:
        quoted = quote(filename, safe="")
        return self.public.generate_presigned_url(
            "get_object",
            ExpiresIn=self.link_seconds,
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ResponseContentDisposition": f"attachment; filename*=UTF-8''{quoted}",
            },
        )

    # shown in the browser rather than saved; anything else (HTML above all, which would run as the
    # storage's origin) is served as a download
    PREVIEWABLE = (
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "application/pdf",
        "text/plain",
        "audio/mpeg",
        "audio/ogg",
        "video/mp4",
        "video/webm",
    )

    def preview_link(self, key: str, content_type: str) -> str:
        shown = content_type if content_type in self.PREVIEWABLE else "application/octet-stream"
        disposition = "inline" if content_type in self.PREVIEWABLE else "attachment"
        return self.public.generate_presigned_url(
            "get_object",
            ExpiresIn=self.link_seconds,
            Params={
                "Bucket": self.bucket,
                "Key": key,
                "ResponseContentType": shown,
                "ResponseContentDisposition": disposition,
            },
        )

    UPLOADS = "uploads/"

    def upload_link(self, key: str, content_type: str) -> str:
        """A signed link the browser PUTs the file's bytes to, with this Content-Type: to the upload's own place."""
        return self.public.generate_presigned_url(
            "put_object",
            ExpiresIn=self.link_seconds,
            Params={"Bucket": self.bucket, "Key": self.UPLOADS + key, "ContentType": content_type},
        )

    def size(self, key: str) -> int | None:
        """The stored object's size, or None if it isn't there."""
        try:
            return int(self.s3.head_object(Bucket=self.bucket, Key=key)["ContentLength"])
        except self.s3.exceptions.ClientError:
            return None

    def accept(self, key: str) -> int | None:
        """The uploaded bytes become the object: moved from the upload's place to `key`. Their size, or None if
        nothing was uploaded. Asked again after it was done (a retry), the object's size."""
        if self.size(self.UPLOADS + key) is None:
            return self.size(key)
        self.s3.copy_object(Bucket=self.bucket, Key=key, CopySource={"Bucket": self.bucket, "Key": self.UPLOADS + key})
        self.s3.delete_object(Bucket=self.bucket, Key=self.UPLOADS + key)
        return self.size(key)

    def discard(self, key: str) -> None:
        """An upload that never finished: its object, and what was uploaded for it."""
        self.delete(key)
        self.delete(self.UPLOADS + key)

    def stored_before(self, older_than: timedelta) -> Iterator[list[str]]:
        """The keys of the objects stored more than that long ago, a page at a time."""
        before, token = datetime.now(UTC) - older_than, ""
        while True:
            more = {"ContinuationToken": token} if token else {}
            page = self.s3.list_objects_v2(Bucket=self.bucket, **more)
            yield [o["Key"] for o in page.get("Contents", []) if o["LastModified"] < before]
            token = page.get("NextContinuationToken", "")
            if not token:
                return

    def sweep_uploads(self, older_than: timedelta) -> int:
        """Removes what is left in the uploads' place after that long (bytes sent again after an upload was
        confirmed, uploads whose rows are gone). How many objects."""
        n = 0
        for keys in self.stored_before(older_than):
            for key in keys:
                if key.startswith(self.UPLOADS):
                    self.s3.delete_object(Bucket=self.bucket, Key=key)
                    n += 1
        return n
