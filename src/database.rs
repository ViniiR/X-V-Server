use std::env::{self, var};

use sqlx::{postgres::PgPoolOptions, PgPool, Pool, Postgres};
use user::User;

pub mod query;
pub mod user;

pub async fn connect_db() -> Pool<Postgres> {
    let username = var("DB_USER").expect("no db user env var");
    let password = var("DB_PASSWORD").expect("no password env var");
    let host = var("DB_HOST").expect("no db host env var");
    let port = var("DB_PORT").expect("no db port env var");
    let dbname = var("DB_NAME").expect("no dbname env var");

    let connection_str: &str = &format!(
        "postgresql://{}:{}@{}:{}/{}",
        username, password, host, port, dbname
    );

    PgPoolOptions::new()
        .max_connections(5)
        .connect(connection_str)
        .await
        .expect("unable to connect to database")
}

pub async fn make_user(user: User, pool: Pool<Postgres>) -> Result<(), &'static str> {
    let result =
        sqlx::query("INSERT INTO users (username, userat, email, password) VALUES ($1,$2,$3,$4);")
            .bind(&user.user_name)
            .bind(&user.user_at)
            .bind(&user.email)
            .bind(&user.password)
            .execute(&pool)
            .await;

    match result {
        Ok(..) => Ok(()),
        Err(e) => {
            dbg!(e);
            Err("Could not create user on db")
        }
    }
}
