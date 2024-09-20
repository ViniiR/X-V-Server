use rocket::{
    http::{CookieJar, Status},
    response::status::Custom,
};

use crate::auth::validate_jwt;

#[get("/auth/validate")]
pub async fn validate(cookies: &CookieJar<'_>) -> Custom<&'static str> {
    match cookies.get_private("auth_key") {
        Some(c) => {
            if let Ok(..) = validate_jwt(c.value()).await {
                Custom(Status::Ok, "Authorized")
            } else {
                Custom(Status::Forbidden, "Invalid JSON Web Token")
            }
        }
        None => Custom(Status::Forbidden, "No credentials"),
    }
}
