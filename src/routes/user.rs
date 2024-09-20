use crate::auth::{create_jwt, hash::hash_str};
use crate::database::{
    connect_db, email_exists, make_jwt_claims, make_user, user::User, verify_password,
};
use crate::{validate_email, validate_minimal_user_credentials, validate_password, LoginData};
use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
    serde::json::Json,
};

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
