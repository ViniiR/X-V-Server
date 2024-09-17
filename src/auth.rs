use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rocket::{
    http::{Cookie, SameSite, Status},
    response::status::Custom,
    time::{Duration, OffsetDateTime},
};

use crate::{database::user::User, Claims, LoginData};

pub mod hash;

pub async fn create_jwt(claims: &str) -> Result<Cookie<'static>, Custom<&'static str>> {
    let mut exp = OffsetDateTime::now_utc();
    exp += Duration::weeks(1);
    let exp = usize::try_from(exp.unix_timestamp()).expect("unable to unwrap UNIX epoch");
    let claims = Claims {
        sub: claims.to_string(),
        exp,
    };

    let jwt_secret = dotenv::var("SECRET_JWT_KEY").expect("SECRET_JWT_KEY not found");

    match encode::<Claims>(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret.as_ref()),
    ) {
        Ok(t) => {
            let mut auth_cookie = Cookie::new("auth_key", t);

            auth_cookie.set_http_only(true);
            let mut now = OffsetDateTime::now_utc();
            now += Duration::weeks(1);

            auth_cookie.set_expires(now);
            auth_cookie.set_secure(true);
            auth_cookie.set_same_site(SameSite::None);
            Ok(auth_cookie)
        }
        Err(..) => Err(Custom(Status::InternalServerError, "InternalServerError")),
    }
}

pub async fn validate_jwt(jwt: &str) -> bool {
    let jwt_secret = dotenv::var("SECRET_JWT_KEY").expect("SECRET_JWT_KEY not found");

    match decode::<Claims>(
        &jwt,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    ) {
        Ok(..) => true,
        Err(..) => false,
    }
}
