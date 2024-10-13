use core::str;

use crate::auth::validate_jwt;
use crate::database::{
    get_client_data, get_email_from_user_at, get_followers_list, get_following_list,
    get_id_from_email, user_exists, FollowData,
};
use crate::routes::types::ProfileData;
use crate::validate_user_at;
use rocket::{
    http::{CookieJar, Status},
    serde::json::{self, Json},
};

use super::types::{DataResponse, UpdatedClientUser, UpdatedFollowData};

#[get("/user/profile/<user_at>", format = "application/json")]
pub async fn get_profile_data(
    user_at: &str,
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<ProfileData, &'static str>> {
    let jwt = cookies.get_private("auth_key");
    // todo
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
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<Vec<UpdatedFollowData>, &'static str>> {
    //let jwt = cookies.get_private("auth_key");
    //let Some(c) = jwt else {
    //    return DataResponse {
    //        status: Status::Forbidden,
    //        data: Json(Err("forbidden")),
    //    };
    //};
    //
    //let Ok(s) = validate_jwt(c.value()).await else {
    //    return DataResponse {
    //        status: Status::Forbidden,
    //        data: Json(Err("forbidden")),
    //    };
    //};

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
    cookies: &CookieJar<'_>,
) -> DataResponse<Result<Vec<UpdatedFollowData>, &'static str>> {
    //let jwt = cookies.get_private("auth_key");
    //let Some(c) = jwt else {
    //    return DataResponse {
    //        status: Status::Forbidden,
    //        data: Json(Err("forbidden")),
    //    };
    //};
    //
    //let Ok(s) = validate_jwt(c.value()).await else {
    //    return DataResponse {
    //        status: Status::Forbidden,
    //        data: Json(Err("forbidden")),
    //    };
    //};

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
