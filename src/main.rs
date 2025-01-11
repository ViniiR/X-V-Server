mod auth;
mod cors;
mod database;
mod routes;

use core::str;
use std::time::{SystemTime, UNIX_EPOCH};

use auth::validate_jwt;
use database::{query_like, user::User, user_has_credentials, Post};
use dotenv::dotenv;
use regex::Regex;
use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
    serde::{json::Json, Deserialize, Serialize},
};
use routes::{
    types::DataResponse,
    user::{PostData, ResponsePost},
};

#[derive(Debug, Deserialize, Serialize)]
struct LoginData {
    #[serde(rename = "email")]
    pub email: String,
    #[serde(rename = "password")]
    pub password: String,
}

struct ValidField {
    valid: bool,
    message: &'static str,
}

#[macro_use]
extern crate rocket;
const EMAIL_REGEX: &str =
    r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})$";

async fn validate_user_name(user_name: &str) -> ValidField {
    let mut is_valid: bool = true;
    let mut message: &str = "";
    let user_name = user_name.trim();
    user_name.chars().for_each(|c| {
        if (!c.is_alphanumeric() && !is_brazilian(c)) || is_spanish(c) {
            is_valid = false;
            message = "username invalid character";
        }
    });
    if user_name.len() < 2 {
        is_valid = false;
        message = "username too short";
    }
    if user_name.len() > 20 {
        is_valid = false;
        message = "username too long";
    }
    ValidField {
        valid: is_valid,
        message,
    }
}

fn is_brazilian(c: char) -> bool {
    c == 'ã' || c == 'á' || c == 'à' || c == 'â'||//a
    c == 'é' || c == 'è' || c == 'ê'||//e
    c == 'í' || c == 'ì' || c == 'î'||//i
    c == 'õ' || c == 'ó' || c == 'ò' || c == 'ô' || //o
    c == 'ú' || c == 'ù' || c == 'û' || //u
    c == 'ç' || // c
    c == 'Ã' || c == 'Á' || c == 'À' || c == 'Â'||//a
    c == 'É' || c == 'È' || c == 'Ê'||//e
    c == 'Í' || c == 'Ì' || c == 'Î'||//i
    c == 'Õ' || c == 'Ó' || c == 'Ò' || c == 'Ô' || //o
    c == 'Ú' || c == 'Ù' || c == 'Û' || //u
    c == 'Ç' // c
}

fn is_spanish(c: char) -> bool {
    c == 'ñ' || c == 'Ñ'
}

async fn validate_user_at(user_at: &str) -> ValidField {
    let mut is_valid: bool = true;
    let user_at = user_at.trim();
    let mut message = "";
    user_at.chars().for_each(|c| {
        if c == '_' {
            return;
        }
        if (!c.is_ascii_alphabetic() && !c.is_numeric() && !is_brazilian(c)) || is_spanish(c) {
            is_valid = false;
            message = "user_at invalid character";
        }
    });
    if user_at.len() < 2 {
        is_valid = false;
        message = "user_at too short";
    }
    if user_at.len() > 20 {
        is_valid = false;
        message = "user_at too long";
    }
    ValidField {
        valid: is_valid,
        message,
    }
}

async fn validate_email(email: &str) -> ValidField {
    let mut is_valid = true;
    let mut message = "";
    let email = email.trim();

    let regex = Regex::new(EMAIL_REGEX).unwrap();

    if !regex.is_match(email) {
        message = "email invalid email";
        is_valid = false;
    }
    //todo!("send EMAIL for verification");
    //its too complex so ill leave it for later or never
    ValidField {
        valid: is_valid,
        message,
    }
}

async fn validate_password(password: &str) -> ValidField {
    let mut is_valid = true;
    let mut message = "";
    let password = password.trim();

    password.chars().for_each(|c| {
        if !c.is_alphanumeric() {
            is_valid = false;
            message = "password invalid character";
        }
    });
    if password.len() < 8 {
        is_valid = false;
        message = "password too short";
    }
    if password.len() > 32 {
        is_valid = false;
        message = "password too long";
    }
    ValidField {
        valid: is_valid,
        message,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

pub async fn validate_minimal_user_credentials(user: &User) -> Result<(), Custom<&'static str>> {
    let res = validate_user_name(&user.user_name).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    let res = validate_user_at(&user.user_at).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    let res = validate_email(&user.email).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    let res = validate_password(&user.password).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    Ok(())
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    rocket::build().attach(cors::CORS).mount(
        "/",
        routes![
            routes::user::create,
            routes::user::login,
            routes::user::logout,
            routes::user::delete,
            routes::auth::validate,
            options,
            routes::user_get::get_data,
            routes::user_get::get_profile_data,
            routes::user_get::get_following,
            routes::user_get::get_followers,
            routes::change::change_profile,
            routes::change::change_password,
            routes::change::change_email,
            routes::change::change_user_at,
            routes::change::follow_user,
            routes::user::publish_post,
            routes::user::fetch_posts,
            routes::user::fetch_post,
            routes::user::fetch_user_posts,
            routes::user::like,
            routes::user::like_comment,
            query,
            comment,
            fetch_comments,
            delete_post,
            delete_comment
        ],
    )
}

#[options("/<_..>")]
async fn options() {}

#[delete("/user/delete-post/<post_id>")]
pub async fn delete_post(post_id: i32, cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    let Some(c) = jwt else {
        return Custom(Status::BadRequest, "BadRequest");
    };
    let Ok(s) = validate_jwt(c.value()).await else {
        return Custom(Status::BadRequest, "BadRequest");
    };

    let pool = crate::database::connect_db().await;
    if user_has_credentials(&s, &pool).await {
        if database::delete_post(&post_id, &pool).await.is_ok() {
            Custom(Status::NoContent, "Post deleted")
        } else {
            Custom(Status::InternalServerError, "InternalServerError")
        }
    } else {
        Custom(Status::BadRequest, "BadRequest")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteCommentData {
    #[serde(rename = "commentId")]
    comment_id: i32,
    #[serde(rename = "ownerPostId")]
    owner_post_id: i32,
}

#[delete(
    "/user/delete-post-comment",
    format = "application/json",
    data = "<comment_delete_data>"
)]
pub async fn delete_comment(
    comment_delete_data: Json<DeleteCommentData>,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    dbg!(&comment_delete_data);
    let jwt = cookies.get_private("auth_key");
    let Some(c) = jwt else {
        return Custom(Status::BadRequest, "BadRequest");
    };
    let Ok(s) = validate_jwt(c.value()).await else {
        return Custom(Status::BadRequest, "BadRequest");
    };
    let comment_delete_data = comment_delete_data.into_inner();

    let pool = crate::database::connect_db().await;
    if user_has_credentials(&s, &pool).await {
        if database::delete_comment(
            &comment_delete_data.comment_id,
            &comment_delete_data.owner_post_id,
            &pool,
        )
        .await
        .is_ok()
        {
            Custom(Status::NoContent, "Comment deleted")
        } else {
            Custom(Status::InternalServerError, "InternalServerError")
        }
    } else {
        Custom(Status::BadRequest, "BadRequest")
    }
}

#[get("/user/fetch-post-comments/<post_id>", format = "application/json")]
pub async fn fetch_comments(
    cookies: &CookieJar<'_>,
    post_id: i32,
) -> DataResponse<Result<Vec<ResponsePost>, &'static str>> {
    dbg!(post_id);
    let pool = database::connect_db().await;

    let Ok(posts) = database::get_comments_from_post(&pool, &post_id).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };
    let mut response_posts: Vec<ResponsePost> = vec![];

    let mut owner_id: Option<i32> = None;

    if let Some(jwt) = cookies.get_private("auth_key") {
        if let Ok(s) = validate_jwt(jwt.value()).await {
            owner_id = Some(s.id);
        };
    };

    for p in posts {
        let Ok(email) = database::get_email_from_id(&p.owner_id, &pool).await else {
            return DataResponse {
                status: Status::InternalServerError,
                data: Json(Err("InternalServerError")),
            };
        };
        let Ok(owner_data) = database::get_client_data(&email, &pool).await else {
            return DataResponse {
                status: Status::InternalServerError,
                data: Json(Err("InternalServerError")),
            };
        };

        let has_this_user_liked = if owner_id.is_none() {
            false
        } else {
            let Ok(c) =
                database::comment_likes_list_contains(&pool, &p.post_id, &owner_id.unwrap()).await
            else {
                return DataResponse {
                    status: Status::InternalServerError,
                    data: Json(Err("InternalServerError")),
                };
            };
            c
        };
        response_posts.push(ResponsePost {
            has_this_user_liked,
            owner_id: p.owner_id,
            post_id: p.post_id,
            unix_time: p.unix_time.to_string(),
            user_at: owner_data.userat,
            username: owner_data.username,
            likes_count: p.likescount,
            comments_count: p.commentscount,
            icon: if owner_data.icon.is_some() {
                let byte_array = owner_data.icon.unwrap_or(vec![]);
                str::from_utf8(&byte_array).unwrap_or("").to_string()
            } else {
                String::from("")
            },
            text: if p.text.is_some() {
                p.text.unwrap()
            } else {
                String::from("")
            },
            image: if p.image.is_some() {
                let byte_array = p.image.unwrap_or(vec![]);
                str::from_utf8(&byte_array).unwrap_or("").to_string()
            } else {
                String::from("")
            },
        });
    }

    DataResponse {
        status: Status::Ok,
        data: Json(Ok(response_posts)),
    }
}

#[patch(
    "/user/comment/<owner_post_id>",
    format = "application/json",
    data = "<post_data>"
)]
pub async fn comment(
    post_data: Json<PostData>,
    owner_post_id: i32,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let date = SystemTime::now();
    let date: i64 = date
        .duration_since(UNIX_EPOCH)
        .expect("We've just stepped on the moon! :D")
        .as_millis() as i64;

    let data = post_data.into_inner();
    const POST_MAX_CHAR_LENGTH: usize = 200;
    let cookie = cookies.get_private("auth_key");
    if data.text.is_none() && data.image.is_none() {
        return Custom(Status::BadRequest, "Bad request, post was empty");
    }
    if data.text.is_some() && data.text.as_ref().unwrap().len() > POST_MAX_CHAR_LENGTH {
        return Custom(Status::BadRequest, "Text too long");
    }
    if cookie.is_none() {
        return Custom(Status::Forbidden, "Forbidden");
    }

    let Ok(s) = validate_jwt(cookie.unwrap().value()).await else {
        return Custom(Status::Forbidden, "Forbidden");
    };

    let pool = database::connect_db().await;

    let text = data.text.unwrap_or(String::from(""));
    if database::comment(&s.id, &text, &data.image, &date, &pool, &owner_post_id)
        .await
        .is_err()
    {
        return Custom(Status::InternalServerError, "InternalServerError");
    };

    Custom(Status::Ok, "Ok")
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserWithIcon {
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "userAt")]
    pub user_at: String,
    #[serde(rename = "icon")]
    pub icon: String,
}

#[get("/user/query/<query>", format = "application/json")]
pub async fn query(query: &str) -> DataResponse<Result<Vec<UserWithIcon>, &'static str>> {
    let mut query_result: Vec<UserWithIcon> = vec![];

    if query.trim().is_empty() {
        return DataResponse {
            status: Status::BadRequest,
            data: Json(Ok(query_result)),
        };
    }

    let pool = database::connect_db().await;
    let query = query_like(query, &pool).await;
    let Ok(q) = query else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Ok(query_result)),
        };
    };

    for i in q {
        query_result.push(UserWithIcon {
            username: i.username,
            user_at: i.userat,
            icon: if i.icon.is_some() {
                let byte_array = i.icon.unwrap_or(vec![]);
                str::from_utf8(&byte_array).unwrap_or("").to_string()
            } else {
                String::from("")
            },
        });
    }

    DataResponse {
        status: Status::Ok,
        data: Json(Ok(query_result)),
    }
}
