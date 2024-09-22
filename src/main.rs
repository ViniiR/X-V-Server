mod auth;
mod cors;
mod database;
mod routes;

use auth::validate_jwt;
use database::{delete_user, get_client_data, user::User, user_has_credentials};
use dotenv::dotenv;
use regex::Regex;
use rocket::{
    http::{ContentType, CookieJar, Status},
    response::{status::Custom, Responder},
    serde::{
        json::{self, Json},
        Deserialize, Serialize,
    },
    Response,
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

pub async fn validate_minimal_user_credentials(user: &User) -> Result<(), Custom<&'static str>> {
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

#[derive(Serialize, Deserialize)]
pub struct ClientUser {
    #[serde(rename = "userName")]
    username: String,
    #[serde(rename = "userAt")]
    userat: String,
    //todo icon: Image?
}

pub struct DataResponse<T> {
    status: Status,
    data: Json<T>,
}

impl<'r, 'o: 'r, T: Serialize> Responder<'r, 'o> for DataResponse<T> {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        Response::build_from(self.data.respond_to(&request).unwrap())
            .status(self.status)
            .header(ContentType::JSON)
            .ok()
    }
}

#[get("/user/data", format = "application/json")]
pub async fn get_data(cookies: &CookieJar<'_>) -> DataResponse<String> {
    let jwt = cookies.get_private("auth_key");

    if let None = jwt {
        return DataResponse {
            status: Status::Forbidden,
            data: Json("xablau?".to_string()),
        };
    }
    if let Ok(s) = validate_jwt(&jwt.unwrap().value()).await {
        let pool = crate::database::connect_db().await;

        if let Ok(c) = get_client_data(&s.email, &pool).await {
            let json_string = json::to_string(&c);
            match json_string {
                Ok(s) => {
                    return DataResponse {
                        status: Status::Ok,
                        data: Json(s),
                    };
                }
                Err(..) => {
                    return DataResponse {
                        status: Status::InternalServerError,
                        data: Json("internal server error".to_string()),
                    };
                }
            }
        } else {
            DataResponse {
                status: Status::Forbidden,
                data: Json("Unauthorized user".to_string()),
            }
        }
    } else {
        DataResponse {
            status: Status::Forbidden,
            data: Json("Unauthorized user".to_string()),
        }
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    rocket::build().attach(cors::CORS).mount(
        "/",
        routes![
            routes::user::create,
            routes::user::login,
            routes::user::logout,
            routes::user::delete,
            routes::auth::validate,
            options,
            get_data,
            routes::change::change_password,
            routes::change::change_email,
            routes::change::change_user_at
        ],
    )
}

#[options("/<_..>")]
async fn options() {}
