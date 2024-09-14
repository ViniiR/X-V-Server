mod auth;
mod database;

use auth::hash::{compare_password, hash_str};
use database::{connect_db, make_user, user::User};
use dotenv::{dotenv, vars};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{Rng, RngCore};
use regex::Regex;
use rocket::{
    http::{Cookie, CookieJar, Status},
    response::status::{BadRequest, Created, Custom},
    serde::{json::Json, Deserialize, Serialize},
    time::{Duration, OffsetDateTime},
};

#[derive(Debug, Deserialize, Serialize)]
struct LoginData {
    #[serde(rename = "email")]
    pub email: String,
    #[serde(rename = "password")]
    pub password: String,
}

struct ValidField {
    valid: bool,
    message: &'static str,
}

#[macro_use]
extern crate rocket;
const EMAIL_REGEX: &'static str =
    r"^([a-z0-9_+]([a-z0-9_+.]*[a-z0-9_+])?)@([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6})$";

async fn validate_user_name(user_name: &str) -> ValidField {
    let mut is_valid: bool = true;
    let mut message: &str = "";
    let user_name = user_name.trim();
    user_name.chars().for_each(|c| {
        if (!c.is_alphanumeric() && !is_brazilian(c)) || is_spanish(c) {
            is_valid = false;
            message = "username invalid character";
        }
    });
    if user_name.len() < 2 {
        is_valid = false;
        message = "username too short";
    }
    if user_name.len() > 20 {
        is_valid = false;
        message = "username too long";
    }
    ValidField {
        valid: is_valid,
        message,
    }
}

fn is_brazilian(c: char) -> bool {
    c == 'ã' || c == 'á' || c == 'à' || c == 'â'||//a
    c == 'é' || c == 'è' || c == 'ê'||//e
    c == 'í' || c == 'ì' || c == 'î'||//i
    c == 'õ' || c == 'ó' || c == 'ò' || c == 'ô' || //o
    c == 'ú' || c == 'ù' || c == 'û' || //u
    c == 'ç' || // c
    c == 'Ã' || c == 'Á' || c == 'À' || c == 'Â'||//a
    c == 'É' || c == 'È' || c == 'Ê'||//e
    c == 'Í' || c == 'Ì' || c == 'Î'||//i
    c == 'Õ' || c == 'Ó' || c == 'Ò' || c == 'Ô' || //o
    c == 'Ú' || c == 'Ù' || c == 'Û' || //u
    c == 'Ç' // c
}

fn is_spanish(c: char) -> bool {
    c == 'ñ' || c == 'Ñ'
}

async fn validate_user_at(user_at: &str) -> ValidField {
    let mut is_valid: bool = true;
    let user_at = user_at.trim();
    let mut message = "";
    user_at.chars().for_each(|c| {
        if c == '_' {
            return;
        }
        if (!c.is_ascii_alphabetic() && !c.is_numeric() && !is_brazilian(c)) || is_spanish(c) {
            is_valid = false;
            message = "user_at invalid character";
        }
    });
    if user_at.len() < 2 {
        is_valid = false;
        message = "user_at too short";
    }
    if user_at.len() > 20 {
        is_valid = false;
        message = "user_at too long";
    }
    ValidField {
        valid: is_valid,
        message,
    }
}

async fn validate_email(email: &str) -> ValidField {
    let mut is_valid = true;
    let mut message = "";
    let email = email.trim();

    let regex = Regex::new(EMAIL_REGEX).unwrap();

    if !regex.is_match(email) {
        message = "email invalid email";
        is_valid = false;
    }
    //todo!("send EMAIL for verification");
    //its too complex so ill leave it for later or never
    ValidField {
        valid: is_valid,
        message,
    }
}

async fn validate_password(password: &str) -> ValidField {
    let mut is_valid = true;
    let mut message = "";
    let password = password.trim();

    password.chars().for_each(|c| {
        if !c.is_numeric() && !c.is_ascii() {
            is_valid = false;
            message = "password invalid character";
        }
    });
    if password.len() < 8 {
        is_valid = false;
        message = "password too short";
    }
    if password.len() > 32 {
        is_valid = false;
        message = "password too long";
    }
    ValidField {
        valid: is_valid,
        message,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

#[post("/user/create", format = "application/json", data = "<form_data>")]
async fn create_user(form_data: Json<User>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let mut data: User = form_data.into_inner();

    let res = validate_user_name(&data.user_name).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
    }

    let res = validate_user_at(&data.user_at).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
    }

    let res = validate_email(&data.email).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
    }

    let res = validate_password(&data.password).await;
    if !res.valid {
        return Custom(Status::BadRequest, res.message);
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

    match make_user(data, pool).await {
        Ok(..) => {
            let mut exp = OffsetDateTime::now_utc();
            exp += Duration::weeks(1);
            let exp = usize::try_from(exp.unix_timestamp()).expect("unable to unwrap UNIX epoch");
            let claims = Claims {
                sub: "?".to_string(),
                company: "?".to_string(),
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
                    dbg!(&auth_cookie);
                    cookies.add_private(auth_cookie);

                    Custom(Status::Created, "User created")
                }
                Err(..) => Custom(Status::InternalServerError, "InternalServerError"),
            }
        }
        Err(e) => e,
    }
}

#[post("/user/login", format = "json", data = "<form_data>")]
fn login_user(form_data: Json<LoginData>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
    let jwt = cookies.get_private("auth_key");
    match jwt {
        Some(..) => {}
        None => {
            return Custom(Status::Forbidden, "Unauthorized user");
        }
    }
    let cookie = jwt.unwrap();
    let cookie = cookie.value();
    let jwt_key = dotenv::var("SECRET_JWT_KEY").expect("jwt_secret not defined");

    match decode::<Claims>(
        &cookie,
        &DecodingKey::from_secret(jwt_key.as_ref()),
        &Validation::default(),
    ) {
        Ok(..) => {
            //
            todo!();
        }
        Err(e) => {
            eprintln!("JWT error: {}", &e);
            Custom(Status::Forbidden, "Invalid JSON Web Token")
        }
    }
}

#[launch]
async fn rocket() -> _ {
    //TODO: move back to each routes in case the db conn breaks
    dotenv().ok();
    rocket::build().mount("/", routes![create_user, login_user])
}
