use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use actix_web::web::{Redirect, Html};
use actix_web::cookie::Key;
use actix_cors::Cors as ActixCors;
use actix_session::{Session, SessionMiddleware};
use actix_session::storage::CookieSessionStore;
use serde::{Serialize, Deserialize};
use jsonwebtoken_rustcrypto::{dangerous_insecure_decode, dangerous_insecure_decode_with_validation, Validation, Algorithm};
#[derive(Deserialize)]
pub struct ActixGetItemsRequest {
    url: String,
}

#[derive(Deserialize)]
pub struct ActixLoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct ActixLoginResponse {
    success: bool,
    message: String,
}

#[derive(Deserialize)]
pub struct ActixPreviewRequest {
    content: String,
    format: String,
}

async fn get_items_actix(
    // CWE 601
    //SOURCE
    request: web::Json<ActixGetItemsRequest>
) -> impl Responder {
    let url = &request.url;

    // CWE 601
    //SINK
    Redirect::to(url.to_string())
}

async fn preview_content_actix(
    // CWE 79
    //SOURCE
    request: web::Json<ActixPreviewRequest>
) -> impl Responder {
    let user_content = &request.content;
    let format_type = &request.format;

    let rendered_html = if format_type == "html" {
        user_content.to_string()
    } else {
        format!(
            "<div class='content-preview'>
                <p>{}</p>
            </div>",
            user_content
        )
    };

    // CWE 79
    //SINK
    Html::new(rendered_html)
}

async fn login_actix(
    // CWE 614
    // CWE 1004
    //SOURCE
    request: web::Json<ActixLoginRequest>,
    session: Session
) -> impl Responder {
    let username = &request.username;
    let password = &request.password;

    let session_data = format!("user:{}|pass:{}", username, password);

    // when we use insert method it triggers actix to set the unsafe cookies (614 and 1004)
    let _ = session.insert("session_token", session_data);
    let _ = session.insert("authenticated", true);

    HttpResponse::Ok().json(ActixLoginResponse {
        success: true,
        message: "Login successful".to_string(),
    })
}

fn configure_actix_cors() -> ActixCors {
    // CWE 942
    //SINK
    ActixCors::permissive()
}

pub async fn launch_actix_api() -> std::io::Result<()> {
    HttpServer::new(move || {
        App::new()
            .wrap(configure_actix_cors())
            .service(
                web::scope("/api")
                    .wrap(
                        SessionMiddleware::builder(
                            CookieSessionStore::default(),
                            Key::generate(),
                        )
                        // CWE 1004
                        //SINK
                        .cookie_http_only(false)
                        // CWE 614
                        //SINK
                        .cookie_secure(false)
                        .build()
                    )
                    .route("/get_items", web::post().to(get_items_actix))
                    .route("/preview_content", web::post().to(preview_content_actix))
                    .route("/login", web::post().to(login_actix))
            )
    })
    .bind("0.0.0.0:3001")?
    .run()
    .await
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
   sub: String
}

pub fn validate_jwt_token_unsafely(token: &str) -> String {
    let validation = Validation::new(Algorithm::HS256);

    //SINK
    match dangerous_insecure_decode_with_validation::<Claims>(token, &validation) {
        Ok(data) => format!("Token valid for subject: {}", data.claims.sub),
        Err(e) => format!("JWT validation error: {e}"),
    }
}