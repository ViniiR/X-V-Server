mod auth;
mod cors;
mod database;

use auth::{create_jwt, hash::hash_str, validate_jwt};
use database::{connect_db, email_exists, make_user, user::User, verify_password};
use dotenv::dotenv;
use regex::Regex;
use rocket::{
    http::{Cookie, CookieJar, SameSite, Status},
    response::status::{Custom, NoContent},
    serde::{json::Json, Deserialize, Serialize},
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
        if !c.is_alphanumeric() {
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
    exp: usize,
}

async fn validate_minimal_user_credentials(user: &User) -> Result<(), Custom<&'static str>> {
    let res = validate_user_name(&user.user_name).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    let res = validate_user_at(&user.user_at).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    let res = validate_email(&user.email).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    let res = validate_password(&user.password).await;
    if !res.valid {
        return Err(Custom(Status::BadRequest, res.message));
    }

    Ok(())
}

#[post("/user/create", format = "application/json", data = "<form_data>")]
async fn create_user(form_data: Json<User>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
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
        Ok(..) => match create_jwt(&data.email).await {
            Ok(c) => {
                cookies.add_private(c);
                Custom(Status::Created, "User created")
            }
            Err(e) => e,
        },
        Err(e) => e,
    }
}

#[post("/user/login", format = "application/json", data = "<form_data>")]
async fn login_user(form_data: Json<LoginData>, cookies: &CookieJar<'_>) -> Custom<&'static str> {
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

    match create_jwt(&data.email).await {
        Ok(c) => {
            cookies.add_private(c);
            Custom(Status::Ok, "Ok")
        }
        Err(e) => e,
    }
}

#[get("/auth/validate")]
async fn validate_user(cookies: &CookieJar<'_>) -> Custom<&'static str> {
    dbg!(cookies.get_private("auth_key"));
    match cookies.get_private("auth_key") {
        Some(c) => {
            if validate_jwt(c.value()).await {
                Custom(Status::Ok, "Authorized")
            } else {
                Custom(Status::Forbidden, "Invalid JSON Web Token")
            }
        }
        None => Custom(Status::Forbidden, "No credentials"),
    }
}

#[options("/<_..>")]
async fn options_handler() -> () {
    ()
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    rocket::build().attach(cors::CORS).mount(
        "/",
        routes![create_user, login_user, validate_user, options_handler],
    )
}
