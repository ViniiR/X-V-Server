use rocket::{
    http::{ContentType, Status},
    response::Responder,
    serde::{json::Json, Deserialize, Serialize},
    Response,
};

#[derive(Deserialize, Serialize, Debug)]
pub struct ProfileData {
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "userAt")]
    pub user_at: String,
    #[serde(rename = "followersCount")]
    pub followers_count: i32,
    #[serde(rename = "followingCount")]
    pub following_count: i32,
    #[serde(rename = "isFollowing")]
    pub is_following: bool,
    #[serde(rename = "isHimself")]
    pub is_himself: bool,
    pub bio: String,
    pub icon: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ProfileUpdate {
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "bio")]
    pub bio: String,
    #[serde(rename = "icon")]
    pub icon: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordChangeData {
    #[serde(rename = "currentPassword")]
    pub current_password: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailChangeData {
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserAtChangeData {
    #[serde(rename = "userAt")]
    pub user_at: String,
}

#[derive(Serialize, Deserialize)]
pub struct UpdatedClientUser {
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "userAt")]
    pub userat: String,
    #[serde(rename = "followingCount")]
    pub followingcount: i32,
    #[serde(rename = "followersCount")]
    pub followerscount: i32,
    pub bio: Option<String>,
    pub icon: String,
}

#[derive(Serialize, Deserialize)]
pub struct ClientUser {
    #[serde(rename = "userName")]
    pub username: String,
    #[serde(rename = "userAt")]
    pub userat: String,
    #[serde(rename = "followingCount")]
    pub followingcount: i32,
    #[serde(rename = "followersCount")]
    pub followerscount: i32,
    pub bio: Option<String>,
    pub icon: Option<Vec<u8>>,
}

pub struct DataResponse<T> {
    pub status: Status,
    pub data: Json<T>,
}

impl<'r, 'o: 'r, T: Serialize> Responder<'r, 'o> for DataResponse<T> {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        Response::build_from(self.data.respond_to(request).unwrap())
            .status(self.status)
            .header(ContentType::JSON)
            .ok()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdatedFollowData {
    #[serde(rename = "userAt")]
    pub user_at: String,
    #[serde(rename = "userName")]
    pub username: String,
    pub icon: String,
}
