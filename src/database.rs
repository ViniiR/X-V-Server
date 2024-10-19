use std::env::var;

use rocket::{http::Status, response::status::Custom};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, query, query_as, Error, Pool, Postgres};
use user::User;

use crate::{
    auth::{hash::compare_password, Sub},
    routes::types::ClientUser,
    PostData,
};

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

pub async fn change_password(
    email: &str,
    new_password: &str,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE users SET password = $1 WHERE email = $2",
        new_password,
        email
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn change_email(
    email: &str,
    new_email: &str,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE users SET email = $1 WHERE email = $2",
        new_email,
        email
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn change_user_at(
    email: &str,
    new_user_at: &str,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE users SET userat = $1 WHERE email = $2",
        new_user_at,
        email
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn verify_password(email: &str, password: &str, pool: &Pool<Postgres>) -> bool {
    match query!("SELECT password FROM users where email = $1", email)
        .fetch_one(pool)
        .await
    {
        Ok(record) => {
            let p: String = record.password;
            dbg!(compare_password(password, &p).await);
            compare_password(password, &p).await
        }
        Err(..) => false,
    }
}

pub struct FollowingDBData {
    followers: Option<Vec<i32>>,
    following: Option<Vec<i32>>,
}

pub async fn get_email_from_id(id: &i32, pool: &Pool<Postgres>) -> Result<String, Error> {
    let email = sqlx::query!("SELECT email FROM users WHERE id = $1", id)
        .fetch_one(pool)
        .await?;

    Ok(email.email)
}

pub async fn delete_user(email: &str, pool: &Pool<Postgres>) -> Result<(), sqlx::Error> {
    let delete_req_id = get_id_from_email(email, pool).await?;
    let unfollow_data = sqlx::query_as!(
        FollowingDBData,
        "SELECT following, followers FROM users WHERE email = $1",
        email
    )
    .fetch_one(pool)
    .await?;
    if unfollow_data.followers.is_some() {
        let followers = unfollow_data.followers.unwrap();
        for id in followers {
            unfollow_user(&delete_req_id, &id, pool).await?;
        }
    }
    if unfollow_data.following.is_some() {
        let following = unfollow_data.following.unwrap();
        for id in following {
            unfollow_user(&id, &delete_req_id, pool).await?;
        }
    }
    sqlx::query!("DELETE FROM users WHERE email = $1", email)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FollowData {
    pub userat: String,
    pub username: String,
    pub icon: Option<Vec<u8>>,
}

pub async fn get_following_list(
    email: &str,
    pool: &Pool<Postgres>,
) -> Result<Vec<FollowData>, Error> {
    let res = sqlx::query!("SELECT following FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await?;

    let mut vec: Vec<FollowData> = vec![];

    let Some(v) = res.following else {
        return Ok(Vec::new());
    };

    for u in v {
        let res = sqlx::query_as!(
            FollowData,
            "SELECT userat, username, icon FROM users WHERE id = $1",
            u
        )
        .fetch_one(pool)
        .await;
        if let Ok(v) = res {
            vec.push(v);
        };
    }

    Ok(vec)
}

pub async fn get_followers_list(
    email: &str,
    pool: &Pool<Postgres>,
) -> Result<Vec<FollowData>, Error> {
    let res = sqlx::query!("SELECT followers FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await?;

    let mut vec: Vec<FollowData> = vec![];

    let Some(v) = res.followers else {
        return Ok(Vec::new());
    };

    for u in v {
        let res = sqlx::query_as!(
            FollowData,
            "SELECT userat, username, icon FROM users WHERE id = $1",
            u
        )
        .fetch_one(pool)
        .await;
        if let Ok(v) = res {
            vec.push(v);
        };
    }

    Ok(vec)
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
        Ok(s) => s.email == sub.email && s.id == sub.id && s.userat == sub.user_at,
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
            id: r.id,
            user_at: r.userat,
            email: r.email,
        }),
        Err(..) => Err(Custom(Status::Forbidden, "User does not exist")),
    }
}

pub async fn get_client_data(email: &str, pool: &Pool<Postgres>) -> Result<ClientUser, ()> {
    let result = sqlx::query_as!(
        ClientUser,
        "SELECT username, userat, followingcount, followerscount, icon, bio FROM users WHERE email = $1",
        email
    )
    .fetch_one(pool)
    .await;

    match result {
        Ok(c) => Ok(c),
        Err(..) => Err(()),
    }
}

pub async fn make_user(user: &User, pool: &Pool<Postgres>) -> Result<(), Custom<&'static str>> {
    if user_exists(&user.user_at, pool).await {
        return Err(Custom(Status::BadRequest, "Username already in use"));
    }
    if email_exists(&user.email, pool).await {
        return Err(Custom(Status::BadRequest, "Email already in use"));
    }

    let result = query!(
        "INSERT INTO users (username, userat, email, password, followingcount, followerscount) VALUES ($1,$2,$3,$4,$5,$6);",
        user.user_name,
        user.user_at,
        user.email,
        user.password,
        0,0
    )
    .execute(pool)
    .await;

    match result {
        Ok(..) => Ok(()),
        Err(..) => Err(Custom(Status::InternalServerError, "Internal server error")),
    }
}

pub async fn get_email_from_user_at(user_at: &str, pool: &Pool<Postgres>) -> Result<String, Error> {
    let email = sqlx::query!("SELECT email FROM users WHERE userat = $1", user_at)
        .fetch_one(pool)
        .await?;
    Ok(email.email)
}

pub async fn get_id_from_email(email: &str, pool: &Pool<Postgres>) -> Result<i32, Error> {
    let id = sqlx::query!("SELECT id FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await?;

    Ok(id.id)
}

pub async fn is_following(
    possibly_followed_owner_id: &i32,
    follow_suspect_id: &i32,
    pool: &Pool<Postgres>,
) -> Result<bool, Error> {
    let res = sqlx::query!(
        "SELECT followers FROM users WHERE id = $1",
        possibly_followed_owner_id,
    )
    .fetch_one(pool)
    .await?;
    let Some(followers) = res.followers else {
        return Ok(false);
    };
    if followers.contains(follow_suspect_id) {
        let res = sqlx::query!(
            "SELECT following FROM users WHERE id = $1",
            follow_suspect_id,
        )
        .fetch_one(pool)
        .await?;
        let Some(following) = res.following else {
            return Ok(false);
        };
        if following.contains(possibly_followed_owner_id) {
            return Ok(true);
        }
    }

    Ok(false)
}

pub async fn follow_user(
    target_id: &i32,
    following_id: &i32,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE users SET followers = array_append(followers, $2), followerscount = followerscount + 1 WHERE id = $1",
        target_id,
        following_id

    )
    .execute(pool)
    .await?;

    sqlx::query!(
        "UPDATE users SET following = array_append(following, $2), followingcount = followingcount + 1 WHERE id = $1",
        following_id,
        target_id,

    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn unfollow_user(
    target_id: &i32,
    unfollowing_id: &i32,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE users SET followers = array_remove(followers, $2), followerscount = followerscount - 1 WHERE id = $1",
        target_id,
        unfollowing_id

    )
    .execute(pool)
    .await?;

    sqlx::query!(
        "UPDATE users SET following = array_remove(following, $2), followingcount = followingcount - 1 WHERE id = $1",
        unfollowing_id,
        target_id,

    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn change_bio(email: &str, bio: &str, pool: &Pool<Postgres>) -> Result<(), Error> {
    let old_bio = sqlx::query!("SELECT bio FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await?;
    let Some(b) = old_bio.bio else {
        sqlx::query!("UPDATE users SET bio = $1 WHERE email = $2", bio, email)
            .execute(pool)
            .await?;
        return Ok(());
    };
    if b != bio {
        sqlx::query!("UPDATE users SET bio = $1 WHERE email = $2", bio, email)
            .execute(pool)
            .await?;
        return Ok(());
    }

    Ok(())
}

pub async fn change_username(
    email: &str,
    username: &str,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    let old_name = sqlx::query!("SELECT username FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await?;
    if old_name.username != username {
        sqlx::query!(
            "UPDATE users SET username = $1 WHERE email = $2",
            username,
            email
        )
        .execute(pool)
        .await?;
        return Ok(());
    }

    Ok(())
}

pub async fn change_icon(email: &str, icon: &str, pool: &Pool<Postgres>) -> Result<(), Error> {
    sqlx::query!(
        "UPDATE users SET icon = $1 WHERE email = $2",
        Some(icon.as_bytes()),
        email
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn post(
    owner_id: &i32,
    text: &str,
    image: &Option<String>,
    unix_time: &i64,
    pool: &Pool<Postgres>,
) -> Result<(), Error> {
    if image.is_none() {
        sqlx::query!(
            "INSERT INTO posts (owner_id, likescount, text, unix_time) VALUES ($1,$2,$3,$4)",
            owner_id,
            0,
            text,
            unix_time,
        )
        .execute(pool)
        .await?;
    } else {
        sqlx::query!(
            "INSERT INTO posts (owner_id, likescount, text, image, unix_time) VALUES ($1,$2,$3,$4,$5)",
            owner_id,
            0,
            text,
            image.as_ref().unwrap().as_bytes(),
            unix_time,
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Post {
    pub text: Option<String>,
    pub image: Option<Vec<u8>>,
    pub owner_id: i32,
    pub likescount: i32,
    pub unix_time: i64,
}

pub async fn get_posts(pool: &Pool<Postgres>) -> Result<Vec<Post>, Error> {
    let res = sqlx::query_as!(
        Post,
        "SELECT text, image, owner_id, likescount, unix_time FROM posts ORDER BY unix_time DESC"
    )
    .fetch_all(pool)
    .await?;
    Ok(res)
}
