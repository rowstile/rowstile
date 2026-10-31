# Files in S3-compatible storage

rowstile decides who may see a row; file contents usually live elsewhere (S3, RustFS, MinIO, R2). The
pattern that keeps the two in step: **the row is the file's permission, and a signed URL is handed out
only after the row was read through row-level security.** [`examples/filemanager/`](../examples/filemanager/) does this, uploads
included (`backend/app/main.py`, `backend/app/storage.py`).

## The table

One row per file, with the object's key in the bucket. Keys are random (a UUID), never derived from
names or ids a user could guess:

```sql
CREATE TABLE app.files (
  id         bigserial PRIMARY KEY,
  folder_id  bigint NOT NULL REFERENCES app.folders,
  name       text NOT NULL,
  object_key uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  size       bigint,                               -- what arrived, once it has
  ready      boolean NOT NULL DEFAULT false        -- the bytes have arrived
);
```

The bucket is private: no public reads, and only the backend holds credentials for it.

## Downloading

```python
with transaction_as(user):                                    # authz.act_as('user', ...)
    row = one("SELECT object_key, name FROM app.files WHERE id = %s AND ready", file_id)
if row is None:
    return 404                                                # hidden and missing look the same
return {"url": s3.generate_presigned_url("get_object", ExpiresIn=600,
        Params={"Bucket": BUCKET, "Key": str(row.object_key),
                "ResponseContentDisposition": f"attachment; filename*=UTF-8''{quote(row.name)}"})}
```

- The `SELECT` is the permission check: row-level security returns the row only to people who may view
  it. There is no separate check to forget.
- Keep links short-lived (minutes). A link is a bearer token: whoever holds it may download until it
  expires, even if access was revoked meanwhile. That window is the price of not proxying the bytes.
- Proxy the bytes through the backend instead when revocation must take effect at once.

## Uploading

Straight from the browser to storage, with the row created first, and the bytes sent to a place of their
own:

1. `INSERT INTO app.files (folder_id, name, ...) VALUES (...) RETURNING id, object_key`: row-level
   security checks the user may add files there (`insert : folder.edit and ...`), with `ready = false`.
2. Return a presigned `PUT` URL for `uploads/<object_key>`, not for the object's own key (the bucket needs a
   CORS rule for your web app's origin).
3. The browser PUTs the bytes.
4. `POST /files/{id}/ready`: the backend reads the row as the user, moves the bytes to the object's key, and
   stores their real size with `ready = true`:

```python
with transaction_as(user):                                    # authz.act_as('user', ...)
    row = one("SELECT object_key FROM app.files WHERE id = %s AND NOT ready", file_id)
    if row is None:
        return 404                                            # hidden, missing or confirmed already
    key = str(row.object_key)
    if size_of("uploads/" + key) is not None:                 # (a retry finds it moved already)
        s3.copy_object(Bucket=BUCKET, Key=key, CopySource={"Bucket": BUCKET, "Key": "uploads/" + key})
        s3.delete_object(Bucket=BUCKET, Key="uploads/" + key)
    size = size_of(key)                                       # head_object's ContentLength, or None
    if size is None:
        return 409                                            # nothing was uploaded
    execute("UPDATE app.files SET ready = true, size = %s WHERE id = %s", size, file_id)
```

- Why a place of its own: a signed `PUT` URL works until it expires, also after the upload was confirmed.
  Signed for the object's own key, it would let its holder replace a confirmed file, and the stored size
  (a quota's count) would no longer be the file's. Moved on confirm, the bytes are out of its reach: what is
  put there later is never read.
- The size the browser gave when the upload started is its word, and a signed `PUT` takes any length: check
  your limit on what arrived (the size above), and delete it if it is over.

Readers only list and download `ready` rows. A periodic job deletes the rows that never became ready (the
upload was abandoned), with their objects and what is in their uploads' place, and anything left in
`uploads/` after a day.

## Deleting

Delete the row through row-level security first (`DELETE ... RETURNING object_key`), commit, then
delete the object. If deleting the object fails, an unreachable object is left behind (clean up later);
the other order could leave a row pointing at nothing.

## Sharing with a link

`authz.create_link()` returns a token once and stores only its hash. A request presenting it
(`SET LOCAL authz_ctx.links = '<token>'`, or `Authz.use_links()` in the Python client) can read what the
link shares, signed in or not, so downloads for link holders follow the same pattern. Send the token
in a header rather than the URL your server logs. `authz.list_links()` lists an object's links for the
people who may turn them off, each with an id, and `authz.revoke_link()` turns one off by that id: the
token is never shown again, and the id opens nothing.
