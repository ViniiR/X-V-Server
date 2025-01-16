use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Header;
use rocket::{Request, Response};

pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to response",
            kind: Kind::Response,
        }
    }
    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new(
            "Access-Control-Allow-Origin",
            dotenv::var("ALLOWED_CLIENT_ORIGIN_URL")
                .expect("ALLOWED_CLIENT_ORIGIN_URL not defined"),
        ));
        response.set_header(Header::new("Access-Control-Allow-Headers", "Content-Type"));
        response.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, PATCH, OPTIONS",
        ));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
        //response.cookies().for_each(|c| {
        //    dbg!(&c);
        //    dbg!(&_request.method());
        //});
        //if _request.method() == Method::Options {
        //    let body = "";
        //    response.set_header(ContentType::Plain);
        //    response.set_sized_body(body.len(), std::io::Cursor::new(body));
        //    response.set_status(Status::Ok);
        //}
    }
}
