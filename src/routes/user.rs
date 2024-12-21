use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::validate_jwt;
use crate::auth::{create_jwt, hash::hash_str};
use crate::database::{self, delete_user, user_has_credentials};
use crate::database::{
    connect_db, email_exists, get_email_from_id, make_jwt_claims, make_user, user::User,
    verify_password,
};
use crate::{validate_email, validate_minimal_user_credentials, validate_password, LoginData};
use core::str;
use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
    serde::json::Json,
};
use serde::{Deserialize, Serialize};

use super::types::DataResponse;

#[post("/user/log-out")]
pub async fn logout(cookies: &CookieJar<'_>) -> Custom<&'static str> {
    match cookies.get_private("auth_key") {
        Some(c) => {
            cookies.remove_private(c);
            Custom(Status::Ok, "Cookie removed")
        }
        None => Custom(
            Status::BadRequest,
            "The JWT didn't even exist... how the fuck did you even request this route? HOW?",
        ),
    }
}

#[post("/user/create", format = "application/json", data = "<form_data>")]
pub async fn create(form_data: Json<User>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let mut data: User = form_data.into_inner();

    if let Err(e) = validate_minimal_user_credentials(&data).await {
        return e;
    }
    match hash_str(&data.password).await {
        Ok(s) => {
            data.password = s;
        }
        Err(..) => {
            return Custom(Status::InternalServerError, "Internal server error");
        }
    }

    let pool = connect_db().await;

    match make_user(&data, &pool).await {
        Ok(..) => {
            //
            let claims = make_jwt_claims(&data.email, &pool).await;
            match claims {
                Ok(c) => match create_jwt(c).await {
                    Ok(c) => {
                        cookies.add_private(c);
                        Custom(Status::Created, "User created")
                    }
                    Err(e) => e,
                },
                Err(e) => e,
            }
        }
        Err(e) => e,
    }
}

#[post("/user/login", format = "application/json", data = "<form_data>")]
pub async fn login(form_data: Json<LoginData>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let data: LoginData = form_data.into_inner();

    let res = validate_email(&data.email).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
    }

    let res = validate_password(&data.password).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
    }

    let pool = connect_db().await;

    if !email_exists(&data.email, &pool).await
        || !verify_password(&data.email, &data.password, &pool).await
    {
        return Custom(Status::BadRequest, "Invalid credentials");
    }

    let claims = make_jwt_claims(&data.email, &pool).await;

    match claims {
        Ok(c) => match create_jwt(c).await {
            Ok(c) => {
                cookies.add_private(c);
                Custom(Status::Ok, "Ok")
            }
            Err(e) => e,
        },
        Err(e) => e,
    }
}

#[delete("/user/delete")]
pub async fn delete(cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    if let Some(c) = jwt {
        if let Ok(s) = validate_jwt(c.value()).await {
            let pool = crate::database::connect_db().await;
            if user_has_credentials(&s, &pool).await {
                if delete_user(&s.email, &pool).await.is_ok() {
                    cookies.remove_private("auth_key");
                    return Custom(Status::NoContent, "User deleted");
                } else {
                    return Custom(Status::InternalServerError, "InternalServerError");
                }
            }
        }
    }

    Custom(Status::Forbidden, "Unauthorized user")
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PostData {
    pub text: Option<String>,
    pub image: Option<String>,
}

#[post(
    "/user/publish-post",
    format = "application/json",
    data = "<post_data>"
)]
pub async fn publish_post(
    post_data: Json<PostData>,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let date = SystemTime::now();
    let date: i64 = date
        .duration_since(UNIX_EPOCH)
        .expect("We're in 1969??")
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
    if database::post(&s.id, &text, &data.image, &date, &pool)
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
    pub unix_time: String,
    #[serde(rename = "postId")]
    pub post_id: i32,
    #[serde(rename = "hasThisUserLiked")]
    pub has_this_user_liked: bool,
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
            let Ok(c) = database::likes_list_contains(&pool, &p.post_id, &owner_id.unwrap()).await
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

#[get("/user/fetch-post/<post_id>", format = "application/json")]
pub async fn fetch_post(
    post_id: i32,
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<ResponsePost, &'static str>> {
    let pool = database::connect_db().await;
    let post = if let Ok(p) = database::get_post_by_id(&pool, &post_id).await {
        p
    } else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    let Ok(email) = get_email_from_id(&post.owner_id, &pool).await else {
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

    let mut owner_id: Option<i32> = None;

    if let Some(jwt) = cookies.get_private("auth_key") {
        if let Ok(s) = validate_jwt(jwt.value()).await {
            owner_id = Some(s.id);
        };
    };

    let has_this_user_liked = if owner_id.is_none() {
        false
    } else {
        let Ok(c) = database::likes_list_contains(&pool, &post.post_id, &owner_id.unwrap()).await
        else {
            return DataResponse {
                status: Status::InternalServerError,
                data: Json(Err("InternalServerError")),
            };
        };
        c
    };
    let response_post = ResponsePost {
        has_this_user_liked,
        owner_id: post.owner_id,
        post_id: post.post_id,
        unix_time: post.unix_time.to_string(),
        user_at: owner_data.userat,
        username: owner_data.username,
        likes_count: post.likescount,
        icon: if owner_data.icon.is_some() {
            let byte_array = owner_data.icon.unwrap_or(vec![]);
            str::from_utf8(&byte_array).unwrap_or("").to_string()
        } else {
            String::from("")
        },
        text: if post.text.is_some() {
            post.text.unwrap()
        } else {
            String::from("")
        },
        image: if post.image.is_some() {
            let byte_array = post.image.unwrap_or(vec![]);
            str::from_utf8(&byte_array).unwrap_or("").to_string()
        } else {
            String::from("")
        },
    };

    DataResponse {
        status: Status::Ok,
        data: Json(Ok(response_post)),
    }
}

#[get("/user/fetch-user-posts/<user_at>", format = "application/json")]
pub async fn fetch_user_posts(
    user_at: String,
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<Vec<ResponsePost>, &'static str>> {
    let pool = database::connect_db().await;

    let email = if let Ok(e) = database::get_email_from_user_at(&user_at, &pool).await {
        e
    } else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };
    let Ok(owner_id) = database::get_id_from_email(&email, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };
    let Ok(posts) = database::get_user_posts(&pool, &owner_id).await else {
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

        let has_this_user_liked = if owner_id.is_none() {
            false
        } else {
            let Ok(c) = database::likes_list_contains(&pool, &p.post_id, &owner_id.unwrap()).await
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

#[derive(Serialize, Deserialize, Debug)]
pub struct LikeInfo {
    post_id: i32,
}

#[patch("/user/like", format = "application/json", data = "<like_info>")]
pub async fn like(cookies: &CookieJar<'_>, like_info: Json<LikeInfo>) -> Status {
    let Some(jwt) = cookies.get_private("auth_key") else {
        return Status::BadRequest;
    };
    let Ok(s) = validate_jwt(jwt.value()).await else {
        return Status::BadRequest;
    };
    let like_info = like_info.into_inner();
    let pool = database::connect_db().await;

    let Ok(has_user_already_liked) =
        database::post_likes_contains(&pool, &like_info.post_id, &s.id).await
    else {
        return Status::InternalServerError;
    };

    if has_user_already_liked {
        let Ok(()) = database::dislike(&pool, &s.id, &like_info.post_id).await else {
            return Status::InternalServerError;
        };
    } else {
        let Ok(()) = database::like(&pool, &s.id, &like_info.post_id).await else {
            return Status::InternalServerError;
        };
    }

    Status::Ok
}
