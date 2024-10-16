mod auth;
mod cors;
mod database;
mod routes;

use core::str;

use auth::validate_jwt;
use database::{get_email_from_id, user::User};
use dotenv::dotenv;
use regex::Regex;
use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
    serde::{json::Json, Deserialize, Serialize},
};
use routes::types::DataResponse;

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

#[derive(Debug, Deserialize, Serialize)]
pub struct PostData {
    pub text: Option<String>,
    pub image: Option<String>,
    #[serde(rename = "unixTime")]
    pub unix_time: isize,
}

#[post(
    "/user/publish-post",
    format = "application/json",
    data = "<post_data>"
)]
async fn publish_post(post_data: Json<PostData>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
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
    if database::post(&s.id, &text, &data.image, &(data.unix_time as i32), &pool)
        .await
        .is_err()
    {
        return Custom(Status::InternalServerError, "InternalServerError");
    }

    Custom(Status::Ok, "Ok")
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ResponsePost {
    pub icon: String,
    pub image: String,
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "userAt")]
    pub user_at: String,
    pub text: String,
    #[serde(rename = "ownerId")]
    pub owner_id: i32,
    #[serde(rename = "likesCount")]
    pub likes_count: i32,
    #[serde(rename = "unixTime")]
    pub unix_time: i32,
    //#[serde(rename = "commentsCount")]
    //pub comments_count: i32,
}

#[get("/user/fetch-posts", format = "application/json")]
pub async fn fetch_posts(
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<Vec<ResponsePost>, &'static str>> {
    let pool = database::connect_db().await;
    let Ok(posts) = database::get_posts(&pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };
    let mut response_posts: Vec<ResponsePost> = vec![];
    for p in posts {
        let Ok(email) = get_email_from_id(&p.owner_id, &pool).await else {
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

        response_posts.push(ResponsePost {
            owner_id: p.owner_id,
            unix_time: p.unix_time,
            user_at: owner_data.userat,
            username: owner_data.username,
            likes_count: p.likescount,
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
            publish_post,
            fetch_posts
        ],
    )
}

#[options("/<_..>")]
async fn options() {}
