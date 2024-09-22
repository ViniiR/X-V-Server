use std::clone;

use rocket::{http::CookieJar, http::Status, response::status::Custom, serde::json::Json};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{create_jwt, hash::hash_str, validate_jwt, Sub},
    database::{self, email_exists, user_exists, user_has_credentials, verify_password},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordChangeData {
    #[serde(rename = "currentPassword")]
    current_password: String,
    #[serde(rename = "newPassword")]
    new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailChangeData {
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserAtChangeData {
    #[serde(rename = "userAt")]
    user_at: String,
}

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
    if let None = jwt {
        return Custom(Status::Forbidden, "Unauthorized user");
    }
    let jwt = jwt.unwrap();
    let data = form_data.into_inner();

    match validate_jwt(&jwt.value()).await {
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
            if let Err(..) = hashed_new_password {
                return Custom(Status::InternalServerError, "InternalServerError");
            }
            let hashed_new_password = hashed_new_password.unwrap();

            if let Ok(..) = database::change_password(email, &hashed_new_password, &pool).await {
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
    if let None = jwt {
        return Custom(Status::Forbidden, "Unauthorized user");
    }

    let jwt = jwt.unwrap();
    let data = form_data.into_inner();

    match validate_jwt(&jwt.value()).await {
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

    if let None = jwt {
        return Custom(Status::Forbidden, "Unauthorized user");
    }

    let jwt = jwt.unwrap();
    let data = form_data.into_inner();

    match validate_jwt(&jwt.value()).await {
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
