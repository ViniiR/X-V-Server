use rocket::{http::CookieJar, http::Status, response::status::Custom, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{create_jwt, hash::hash_str, validate_jwt, Sub},
    database::{self, email_exists, user_exists, user_has_credentials, verify_password},
    validate_email, validate_password, validate_user_at, validate_user_name, ValidField,
    BIO_MAX_LEN,
};

use super::types::{EmailChangeData, PasswordChangeData, ProfileUpdate, UserAtChangeData};

#[patch(
    "/user/change/password",
    format = "application/json",
    data = "<form_data>"
)]
pub async fn change_password(
    form_data: Json<PasswordChangeData>,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    if jwt.is_none() {
        return Custom(Status::Forbidden, "Unauthorized user");
    }
    let jwt = jwt.unwrap();
    let data = form_data.into_inner();

    // TODO(MAYBE) add separate messages for old and new password although i dont think its
    // necessary
    let valid_password = validate_password(&data.new_password).await;
    if !valid_password.valid {
        return Custom(Status::BadRequest, valid_password.message);
    }

    match validate_jwt(jwt.value()).await {
        Ok(s) => {
            let pool = database::connect_db().await;

            if !user_has_credentials(&s, &pool).await {
                return Custom(Status::Forbidden, "Unauthorized user");
            }
            let email = &s.email;

            if !verify_password(email, &data.current_password, &pool).await {
                return Custom(Status::Forbidden, "Current password doesn't match");
            }

            if verify_password(email, &data.new_password, &pool).await {
                return Custom(
                    Status::BadRequest,
                    "New password cannot be the same as the old one",
                );
            }

            let hashed_new_password = hash_str(&data.new_password).await;
            if hashed_new_password.is_err() {
                return Custom(Status::InternalServerError, "InternalServerError");
            }
            let hashed_new_password = hashed_new_password.unwrap();

            if database::change_password(email, &hashed_new_password, &pool)
                .await
                .is_ok()
            {
                return Custom(Status::Ok, "Password changed succesfully");
            }

            Custom(Status::InternalServerError, "InternalServerError")
        }
        Err(..) => Custom(Status::Forbidden, "Unauthorized user"),
    }
}

#[patch(
    "/user/change/email",
    format = "application/json",
    data = "<form_data>"
)]
pub async fn change_email(
    form_data: Json<EmailChangeData>,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    if jwt.is_none() {
        return Custom(Status::Forbidden, "Unauthorized user");
    }

    let jwt = jwt.unwrap();
    let mut data = form_data.into_inner();
    data.email = data.email.to_lowercase().trim().to_string();

    let valid_email = validate_email(&data.email).await;
    if !valid_email.valid {
        return Custom(Status::BadRequest, valid_email.message);
    }

    match validate_jwt(jwt.value()).await {
        Ok(s) => {
            let pool = database::connect_db().await;
            if !user_has_credentials(&s, &pool).await {
                return Custom(Status::Forbidden, "Unauthorized user");
            }

            if s.email == data.email {
                return Custom(
                    Status::BadRequest,
                    "New email cannot be the same as the old one",
                );
            }

            if email_exists(&data.email, &pool).await {
                return Custom(Status::BadRequest, "Email already exists");
            }

            if let Ok(()) = database::change_email(&s.email, &data.email, &pool).await {
                match create_jwt(Sub {
                    id: s.id.to_owned(),
                    email: data.email.to_owned(),
                    user_at: s.user_at.to_owned(),
                })
                .await
                {
                    Ok(c) => {
                        cookies.add_private(c);
                        return Custom(Status::Ok, "Email changed succesfully");
                    }
                    Err(..) => {
                        return Custom(Status::InternalServerError, "InternalServerError");
                    }
                }
            }

            Custom(Status::InternalServerError, "InternalServerError")
        }
        Err(..) => Custom(Status::Forbidden, "Unauthorized user"),
    }
}
#[patch(
    "/user/change/user-at",
    format = "application/json",
    data = "<form_data>"
)]
pub async fn change_user_at(
    form_data: Json<UserAtChangeData>,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");

    if jwt.is_none() {
        return Custom(Status::Forbidden, "Unauthorized user");
    }

    let jwt = jwt.unwrap();
    let mut data = form_data.into_inner();
    data.user_at = data.user_at.to_lowercase();
    if data.user_at.starts_with('@') {
        data.user_at.remove(0);
    }

    let valid_user_at = validate_user_at(&data.user_at).await;
    if !valid_user_at.valid {
        return Custom(Status::BadRequest, valid_user_at.message);
    }

    match validate_jwt(jwt.value()).await {
        Ok(s) => {
            let pool = database::connect_db().await;

            if data.user_at == s.user_at {
                return Custom(
                    Status::BadRequest,
                    "New userat cannot be the same as the old one",
                );
            }

            if !user_has_credentials(&s, &pool).await {
                return Custom(Status::Forbidden, "Unauthorized user");
            }

            if user_exists(&data.user_at, &pool).await {
                return Custom(Status::BadRequest, "UserAt already in use");
            }

            if let Ok(()) = database::change_user_at(&s.email, &data.user_at, &pool).await {
                match create_jwt(Sub {
                    id: s.id.to_owned(),
                    user_at: data.user_at.to_owned(),
                    email: s.email.to_owned(),
                })
                .await
                {
                    Ok(c) => {
                        cookies.add_private(c);
                        return Custom(Status::Ok, "User_at changed succesfully");
                    }
                    Err(..) => {
                        return Custom(Status::InternalServerError, "InternalServerError");
                    }
                }
            }

            Custom(Status::InternalServerError, "InternalServerError")
        }
        Err(..) => Custom(Status::Forbidden, "Unauthorized user"),
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FollowData {
    user_at: String,
    follow: bool,
    icon: Option<Vec<i32>>,
}

#[patch("/user/follow", format = "application/json", data = "<data>")]
pub async fn follow_user(data: Json<FollowData>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    let data = data.into_inner();

    let Some(cookie) = jwt else {
        return Custom(Status::Forbidden, "Unauthorized");
    };

    let Ok(sub) = validate_jwt(cookie.value()).await else {
        return Custom(Status::Forbidden, "Unauthorized");
    };

    if sub.user_at == data.user_at {
        return Custom(Status::BadRequest, "You can't follow yourself");
    }

    let pool = database::connect_db().await;

    if !user_exists(&sub.user_at, &pool).await {
        return Custom(Status::Forbidden, "Unauthorized");
    }

    if !user_exists(&data.user_at, &pool).await {
        return Custom(Status::BadRequest, "User doesn't exist");
    }

    let Ok(follow_target_email) = database::get_email_from_user_at(&data.user_at, &pool).await
    else {
        return Custom(Status::InternalServerError, "InternalServerError");
    };

    let Ok(follow_target_id) = database::get_id_from_email(&follow_target_email, &pool).await
    else {
        return Custom(Status::InternalServerError, "InternalServerError");
    };

    if data.follow {
        let Ok(..) = database::follow_user(&follow_target_id, &sub.id, &pool).await else {
            return Custom(Status::InternalServerError, "InternalServerError");
        };
    } else {
        let Ok(..) = database::unfollow_user(&follow_target_id, &sub.id, &pool).await else {
            return Custom(Status::InternalServerError, "InternalServerError");
        };
    }
    Custom(Status::Ok, "Ok")
}

#[patch(
    "/user/change/profile",
    format = "application/json",
    data = "<profile_data>"
)]
pub async fn change_profile(
    profile_data: Json<ProfileUpdate>,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    if jwt.is_none() {
        return Custom(Status::Forbidden, "forbidden");
    }

    let jwt = jwt.unwrap();

    let Ok(s) = validate_jwt(jwt.value()).await else {
        return Custom(Status::Forbidden, "forbidden");
    };

    if profile_data.bio.chars().count() > BIO_MAX_LEN {
        return Custom(Status::BadRequest, "bio too long");
    }

    let res: ValidField = validate_user_name(&profile_data.username).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
    }

    if !(crate::validate_user_name(&profile_data.username).await).valid {
        return Custom(Status::BadRequest, "username invalid");
    }

    let pool = database::connect_db().await;

    if database::change_bio(&s.email, &profile_data.bio, &pool)
        .await
        .is_err()
    {
        return Custom(Status::InternalServerError, "InternalServerError");
    }

    if database::change_username(&s.email, &profile_data.username, &pool)
        .await
        .is_err()
    {
        return Custom(Status::InternalServerError, "InternalServerError");
    }

    if database::change_icon(&s.email, &profile_data.icon, &pool)
        .await
        .is_err()
    {
        return Custom(Status::InternalServerError, "InternalServerError");
    }

    Custom(Status::Ok, "Ok")
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EditPostData {
    pub text: String,
    pub image: String,
}

#[patch(
    "/user/edit-post/<post_id>",
    format = "application/json",
    data = "<data>"
)]
pub async fn edit_post(
    data: Json<EditPostData>,
    post_id: i32,
    cookies: &CookieJar<'_>,
) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    if jwt.is_none() {
        return Custom(Status::Forbidden, "forbidden");
    }

    let jwt = jwt.unwrap();

    let Ok(s) = validate_jwt(jwt.value()).await else {
        return Custom(Status::Forbidden, "forbidden");
    };
    let pool = database::connect_db().await;

    if !database::user_has_credentials(&s, &pool).await {
        return Custom(Status::Forbidden, "forbidden");
    }

    let data = data.into_inner();

    if database::edit_post(&post_id, &data, &pool).await.is_err() {
        return Custom(Status::InternalServerError, "InternalServerError");
    }
    Custom(Status::Ok, "post edited")
}
