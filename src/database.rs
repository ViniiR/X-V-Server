use core::{error, panic};
use std::env::var;

use rocket::{http::Status, response::status::Custom};
use sqlx::{postgres::PgPoolOptions, query, query_as, Pool, Postgres};
use user::User;

use crate::auth::{hash::compare_password, Sub};

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
    match query!("SELECT * FROM users WHERE email = $1", email)
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
            let p: String = record.password;
            compare_password(password, &p).await
        }
        Err(..) => false,
    }
}

pub async fn delete_user(email: &str, pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM users WHERE email = $1", email)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn user_has_credentials(sub: &Sub, pool: &Pool<Postgres>) -> bool {
    let result = sqlx::query_as!(
        UserWithID,
        "SELECT email, userat, id FROM users WHERE email = $1",
        sub.email
    )
    .fetch_one(pool)
    .await;

    match result {
        Ok(s) => {
            if s.email == sub.email && s.id as u32 == sub.id && s.userat == sub.user_at {
                true
            } else {
                false
            }
        }
        Err(..) => false,
    }
}

#[derive(Debug)]
pub struct UserWithID {
    pub email: String,
    pub userat: String,
    pub id: i32,
}

pub async fn make_jwt_claims(
    email: &str,
    pool: &Pool<Postgres>,
) -> Result<Sub, Custom<&'static str>> {
    let result = query_as!(
        UserWithID,
        "SELECT id, userat, email FROM users WHERE email = $1",
        email
    )
    .fetch_one(pool)
    .await;

    match result {
        Ok(r) => Ok(Sub {
            id: r.id as u32,
            user_at: r.userat,
            email: r.email,
        }),
        Err(..) => Err(Custom(Status::Forbidden, "User does not exist")),
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
