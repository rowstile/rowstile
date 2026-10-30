//! sqlx's migrator, as `sqlx migrate run` and `sqlx migrate info` run it, on the migrations folder:
//!   migrate URL [DIR]          applies what DIR (migrations) holds that the database hasn't, and says which
//!   migrate --info URL [DIR]   each migration, installed or pending, and whether its file is the one applied
//! (sqlx-cli is the same library, built as a command: not built here, for its minutes of compiling)

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use sqlx::migrate::{Migrate, Migrator};
use sqlx::{Connection, PgConnection};

#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let info = args.first().is_some_and(|a| a == "--info");
    if info {
        args.remove(0);
    }
    let dir = args.get(1).map_or("migrations", String::as_str);
    match run(&args[0], Path::new(dir), info).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(url: &str, dir: &Path, info: bool) -> Result<(), Box<dyn std::error::Error>> {
    let migrator = Migrator::new(dir).await?;
    let mut conn = PgConnection::connect(url).await?;
    if !info {
        let before: Vec<i64> = applied(&mut conn).await?.into_keys().collect();
        migrator.run(&mut conn).await?;
        for m in migrator.iter().filter(|m| !before.contains(&m.version)) {
            println!("applied {}/{} {}", dir.display(), m.version, m.description);
        }
        return Ok(());
    }
    let applied = applied(&mut conn).await?;
    for m in migrator.iter() {
        let state = match applied.get(&m.version) {
            None => "pending",
            Some(sum) if *sum == m.checksum.as_ref() => "installed",
            Some(_) => "installed (different checksum)",
        };
        println!("{}/{} {}: {state}", dir.display(), m.version, m.description);
    }
    Ok(())
}

/// the versions the database has applied, and each one's checksum
async fn applied(conn: &mut PgConnection) -> Result<HashMap<i64, Vec<u8>>, Box<dyn std::error::Error>> {
    conn.ensure_migrations_table("_sqlx_migrations").await?;
    let done = conn.list_applied_migrations("_sqlx_migrations").await?;
    Ok(done.into_iter().map(|m| (m.version, m.checksum.into_owned())).collect())
}
