"""The queues, on Redis: Celery's (celery -A app.worker worker) and RQ's (rq worker conformance). A request puts a
job on one, and a worker process runs it: the functions of app/jobs.py, the same for both."""

import asyncio
import os

from celery import Celery
from redis import Redis
from rq import Queue

from . import jobs

REDIS = os.environ.get("ROWSTILE_REDIS_URL", "redis://localhost:6379/0")

celery = Celery("conformance", broker=REDIS, backend=REDIS)
celery.conf.broker_connection_retry_on_startup = True
digest = celery.task(jobs.digest)
add_note = celery.task(jobs.add_note)
edit_note = celery.task(jobs.edit_note)
remove_note = celery.task(jobs.remove_note)
notes_seen = celery.task(jobs.notes_seen)
left_behind = celery.task(jobs.left_behind)


@celery.task
def digest_async() -> int:
    """Celery runs no coroutine itself: the job runs in an event loop of its own."""
    return asyncio.run(jobs.digest_async())


queue = Queue("conformance", connection=Redis.from_url(REDIS))
