use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
};

use crate::{
    auth::validate_jwt,
    database::{self, user_exists},
};

#[get("/auth/validate")]
pub async fn validate(cookies: &CookieJar<'_>) -> Custom<&'static str> {
    match cookies.get("auth_key") {
        Some(c) => {
            if let Ok(s) = validate_jwt(c.value()).await {
                let pool = database::connect_db().await;
                if !user_exists(&s.user_at, &pool).await {
                    return Custom(Status::Forbidden, "Invalid JSON Web Token");
                }
                Custom(Status::Ok, "Authorized")
            } else {
                Custom(Status::Forbidden, "Invalid JSON Web Token")
            }
        }
        None => Custom(Status::Forbidden, "No credentials"),
    }
}
