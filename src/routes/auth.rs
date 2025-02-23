use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
};

use crate::{
    auth::validate_jwt,
    //database::{self, user_exists},
};

#[get("/auth/validate")]
pub async fn validate(cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let Some(c) = cookies.get_private("auth_key") else {
        return Custom(Status::Forbidden, "No credentials");
    };

    let Ok(_s) = validate_jwt(c.value()).await else {
        return Custom(Status::Forbidden, "Invalid JSON Web Token");
    };

    //let pool = database::connect_db().await;
    //
    //if !user_exists(&s.user_at, &pool).await {
    //    return Custom(Status::Forbidden, "Invalid JSON Web Token");
    //}
    Custom(Status::Ok, "Authorized")
}
