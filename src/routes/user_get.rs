use core::str;

use crate::auth::validate_jwt;
use crate::database::{
    get_client_data, get_email_from_user_at, get_followers_list, get_following_list,
    get_id_from_email, user_exists,
};
use crate::routes::types::ProfileData;
use crate::validate_user_at;
use rocket::{
    http::{CookieJar, Status},
    serde::json::{self, Json},
};
use serde::{Deserialize, Serialize};

use super::types::{DataResponse, UpdatedClientUser, UpdatedFollowData};
use super::user::ResponsePost;

#[get("/user/profile/<user_at>", format = "application/json")]
pub async fn get_profile_data(
    user_at: &str,
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<ProfileData, &'static str>> {
    let jwt = cookies.get_private("auth_key");
    let mut is_following = false;
    let mut is_himself = false;

    if !(validate_user_at(user_at).await).valid {
        return DataResponse {
            status: Status::NotFound,
            data: Json(Err("Not found")),
        };
    }

    let pool = crate::database::connect_db().await;

    if !user_exists(user_at, &pool).await {
        return DataResponse {
            status: Status::NotFound,
            data: Json(Err("Not found")),
        };
    }

    let Ok(email) = get_email_from_user_at(user_at, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    if let Ok(id) = get_id_from_email(&email, &pool).await {
        if let Some(c) = jwt {
            let Ok(s) = validate_jwt(c.value()).await else {
                return DataResponse {
                    status: Status::Forbidden,
                    data: Json(Err("Unauthorized user")),
                };
            };

            if s.id == id {
                is_himself = true;
            }

            if !user_exists(&s.user_at, &pool).await {
                return DataResponse {
                    status: Status::Forbidden,
                    data: Json(Err("Unauthorized user")),
                };
            }

            if let Ok(b) = crate::database::is_following(&id, &s.id, &pool).await {
                is_following = b;
            }
        }
    }

    let Ok(data) = get_client_data(&email, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    DataResponse {
        status: Status::Ok,
        data: Json(Ok(ProfileData {
            user_at: data.userat,
            username: data.username,
            is_following,
            following_count: data.followingcount,
            followers_count: data.followerscount,
            is_himself,
            icon: if data.icon.is_none() {
                String::new()
            } else {
                str::from_utf8(&data.icon.unwrap()).unwrap().to_owned()
            },
            bio: if data.bio.is_none() {
                String::new()
            } else {
                data.bio.unwrap()
            },
        })),
    }
}

#[get("/user/data", format = "application/json")]
pub async fn get_data(cookies: &CookieJar<'_>) -> DataResponse<String> {
    let jwt = cookies.get_private("auth_key");

    if jwt.is_none() {
        return DataResponse {
            status: Status::Forbidden,
            data: Json("Unauthorized user".to_string()),
        };
    }
    if let Ok(s) = validate_jwt(jwt.unwrap().value()).await {
        let pool = crate::database::connect_db().await;

        if let Ok(c) = get_client_data(&s.email, &pool).await {
            let updated: UpdatedClientUser = UpdatedClientUser {
                username: c.username,
                userat: c.userat,
                bio: c.bio,
                followingcount: c.followingcount,
                followerscount: c.followerscount,
                icon: if c.icon.is_none() {
                    String::new()
                } else {
                    str::from_utf8(&c.icon.unwrap()).unwrap().to_owned()
                },
            };
            let json_string = json::to_string(&updated);
            match json_string {
                Ok(s) => DataResponse {
                    status: Status::Ok,
                    data: Json(s),
                },
                Err(..) => DataResponse {
                    status: Status::InternalServerError,
                    data: Json("internal server error".to_string()),
                },
            }
        } else {
            DataResponse {
                status: Status::Forbidden,
                data: Json("Unauthorized user".to_string()),
            }
        }
    } else {
        DataResponse {
            status: Status::Forbidden,
            data: Json("Unauthorized user".to_string()),
        }
    }
}

#[get("/user/following/<user_at>")]
pub async fn get_following(
    user_at: &str,
) -> DataResponse<Result<Vec<UpdatedFollowData>, &'static str>> {
    let pool = crate::database::connect_db().await;
    let Ok(email) = get_email_from_user_at(user_at, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    let Ok(v) = get_following_list(&email, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    let mut updated: Vec<UpdatedFollowData> = vec![];
    for f in v {
        let u = UpdatedFollowData {
            user_at: f.userat,
            username: f.username,
            icon: if f.icon.is_none() {
                String::new()
            } else {
                str::from_utf8(&f.icon.unwrap()).unwrap().to_owned()
            },
        };
        updated.push(u);
    }

    DataResponse {
        status: Status::Ok,
        data: Json(Ok(updated)),
    }
}

#[get("/user/followers/<user_at>")]
pub async fn get_followers(
    user_at: &str,
) -> DataResponse<Result<Vec<UpdatedFollowData>, &'static str>> {
    let pool = crate::database::connect_db().await;
    let Ok(email) = get_email_from_user_at(user_at, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    let Ok(v) = get_followers_list(&email, &pool).await else {
        return DataResponse {
            status: Status::InternalServerError,
            data: Json(Err("InternalServerError")),
        };
    };

    let mut updated: Vec<UpdatedFollowData> = vec![];
    for f in v {
        let u = UpdatedFollowData {
            user_at: f.userat,
            username: f.username,
            icon: if f.icon.is_none() {
                String::new()
            } else {
                str::from_utf8(&f.icon.unwrap()).unwrap().to_owned()
            },
        };
        updated.push(u);
    }

    DataResponse {
        status: Status::Ok,
        data: Json(Ok(updated)),
    }
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

    let pool = crate::database::connect_db().await;
    let query = crate::database::query_like(query, &pool).await;
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

#[get("/user/fetch-post-comments/<post_id>", format = "application/json")]
pub async fn fetch_comments(
    cookies: &CookieJar<'_>,
    post_id: i32,
) -> DataResponse<Result<Vec<ResponsePost>, &'static str>> {
    dbg!(post_id);
    let pool = crate::database::connect_db().await;

    let Ok(posts) = crate::database::get_comments_from_post(&pool, &post_id).await else {
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
        let Ok(email) = crate::database::get_email_from_id(&p.owner_id, &pool).await else {
            return DataResponse {
                status: Status::InternalServerError,
                data: Json(Err("InternalServerError")),
            };
        };
        let Ok(owner_data) = crate::database::get_client_data(&email, &pool).await else {
            return DataResponse {
                status: Status::InternalServerError,
                data: Json(Err("InternalServerError")),
            };
        };

        let has_this_user_liked = if owner_id.is_none() {
            false
        } else {
            let Ok(c) =
                crate::database::comment_likes_list_contains(&pool, &p.post_id, &owner_id.unwrap())
                    .await
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
