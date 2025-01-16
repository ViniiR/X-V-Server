use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::{
    http::{Cookie, SameSite, Status},
    response::status::Custom,
    serde::json,
    time::{Duration, OffsetDateTime},
};
use serde::{Deserialize, Serialize};

use crate::Claims;

pub mod hash;

#[derive(Debug, Serialize, Deserialize)]
pub struct Sub {
    pub id: i32,
    pub user_at: String,
    pub email: String,
}

pub async fn create_jwt(claims: Sub) -> Result<Cookie<'static>, Custom<&'static str>> {
    let mut exp = OffsetDateTime::now_utc();
    exp += Duration::weeks(1);
    let exp = usize::try_from(exp.unix_timestamp()).expect("unable to unwrap UNIX epoch");
    let claims = Claims {
        sub: json::to_string(&claims).expect("unable to convert to string"),
        exp,
    };

    let jwt_secret = dotenv::var("SECRET_JWT_KEY").expect("SECRET_JWT_KEY not found");

    match encode::<Claims>(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    ) {
        Ok(t) => {
            let mut auth_cookie = Cookie::new("auth_key", t);

            auth_cookie.set_http_only(true);
            let mut now = OffsetDateTime::now_utc();
            now += Duration::weeks(1);

            auth_cookie.set_expires(now);
            auth_cookie.set_secure(true);
            auth_cookie.set_same_site(SameSite::None);
            auth_cookie.set_path("/");
            Ok(auth_cookie)
        }
        Err(..) => Err(Custom(Status::InternalServerError, "InternalServerError")),
    }
}

pub async fn validate_jwt(jwt: &str) -> Result<Sub, ()> {
    let jwt_secret = dotenv::var("SECRET_JWT_KEY").expect("SECRET_JWT_KEY not found");

    match decode::<Claims>(
        &jwt,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(c) => {
            let sub = c.claims.sub;
            let sub: Sub = json::from_str(&sub).unwrap();
            Ok(sub)
        }
        Err(..) => Err(()),
    }
}
