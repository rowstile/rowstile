// A queue (BullMQ, on Redis): the app queues the digest, and a worker runs it as service 1, whoever queued it
import { Queue, Worker } from "bullmq";
import { digest } from "./jobs.ts";

const connection = { url: process.env.REDIS_URL, maxRetriesPerRequest: null };

// made on first use: next build loads the routes, with no Redis to reach
let queue: Queue | undefined;
export const digests = () => (queue ??= new Queue("digest", { connection }));

// the worker runs the job as job() says: signed in as service 1
export const digestWorker = () => new Worker("digest", digest, { connection });
