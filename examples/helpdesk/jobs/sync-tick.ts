// The sync index's clock, which runs beside the app. A share that ends or begins with time (break glass's, an
// hour on) changes who may read a ticket with no write, so nothing tells the sync index, and Electric would keep
// serving the ticket. authz.sync_tick() works those tickets' readers out again, and Electric then sends the
// move-out. It is for administrators (the app role can't call it), so this runs as the tables' owner, in a
// process of its own: the web server never holds the owner's password. test.sh starts it; a deployment runs it as
// a service of its own, or schedules the one statement (pg_cron, a CronJob).
//   DATABASE_URL=postgresql://hd_owner:...@localhost:25434/helpdesk npm run tick     # every minute
//   HD_TICK_SECONDS=1 npm run tick                                                   # every second
import pg from "pg";

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL: the tables' owner's connection (authz.sync_tick() is for administrators)");
const every = Number(process.env.HD_TICK_SECONDS ?? 60) * 1000;
const pool = new pg.Pool({ connectionString: url, max: 1 });

async function tick(): Promise<void> {
  try {
    const { rows } = await pool.query<{ shares: string }>("SELECT authz.sync_tick() AS shares");
    const shares = Number(rows[0]?.shares ?? 0);
    if (shares > 0) console.log(`${new Date().toISOString()} ${shares} share(s) began or ended: their readers worked out again`);
  } catch (e) {
    console.error(`${new Date().toISOString()} authz.sync_tick(): ${(e as Error).message}`); // the next tick tries again
  }
  setTimeout(() => void tick(), every);
}

void tick();
