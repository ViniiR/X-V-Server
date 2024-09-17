use std::env::var;

use rocket::{http::Status, response::status::Custom};
use sqlx::{postgres::PgPoolOptions, query, Pool, Postgres};
use user::User;

use crate::auth::hash::compare_password;

pub mod user;

pub async fn connect_db() -> Pool<Postgres> {
    let connection_str: &str = &var("DATABASE_URL").unwrap();
    PgPoolOptions::new()
        .max_connections(10)
        .connect(connection_str)
        .await
        .expect("unable to connect to database")
}

pub async fn user_exists(user_at: &str, pool: &Pool<Postgres>) -> bool {
    match query!("SELECT FROM users WHERE userat = $1", user_at)
        .fetch_one(pool)
        .await
    {
        Ok(..) => true,
        Err(..) => false,
    }
}

pub async fn email_exists(email: &str, pool: &Pool<Postgres>) -> bool {
    match query!("SELECT FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await
    {
        Ok(..) => true,
        Err(..) => false,
    }
}

pub async fn verify_password(email: &str, password: &str, pool: &Pool<Postgres>) -> bool {
    match query!("SELECT password FROM users where email = $1", email)
        .fetch_one(pool)
        .await
    {
        Ok(record) => {
            let p: String = record.password.unwrap_or(String::new());
            compare_password(password, &p).await
        }
        Err(..) => false,
    }
}

pub async fn make_user(user: &User, pool: &Pool<Postgres>) -> Result<(), Custom<&'static str>> {
    if user_exists(&user.user_at, &pool).await {
        return Err(Custom(Status::BadRequest, "Username already in use"));
    }
    if email_exists(&user.email, &pool).await {
        return Err(Custom(Status::BadRequest, "Email already in use"));
    }

    let result = query!(
        "INSERT INTO users (username, userat, email, password) VALUES ($1,$2,$3,$4);",
        user.user_name,
        user.user_at,
        user.email,
        user.password
    )
    .execute(pool)
    .await;

    match result {
        Ok(..) => Ok(()),
        Err(..) => Err(Custom(Status::InternalServerError, "Internal server error")),
    }
}
