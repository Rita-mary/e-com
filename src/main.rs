use actix_web::{HttpMessage, HttpRequest ,  Error, Result};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use models::Product;
use mongodb::bson::doc;
use mongodb::Collection;
use argon2::{self, Config as ArgonConfig};
use uuid::Uuid;
use jsonwebtoken::{encode, Header, EncodingKey};
use std::env;
use rand::Rng; 
use serde_json::json;
use futures::stream::StreamExt;

mod db;
mod models;
mod middleware;

async fn sign_up(db: web::Data<Collection<models::User>>, new_user: web::Json<models::SignUpInput>)-> impl Responder{

    let salt: [u8; 16] = rand::thread_rng().gen();
    let config = ArgonConfig::default();
    
    // Hash the password
    let hashed_password = match argon2::hash_encoded(new_user.password.as_bytes(), &salt, &config) {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Password hashing failed: {}", e);
            return HttpResponse::InternalServerError().json("Internal Server Error");
        }
    };

    let new_account = models::User{
        id: Uuid::new_v4().to_string(),
        name: new_user.name.clone(),
        email: new_user.email.clone(),
        password: hashed_password,
    };

    let result = db.insert_one(&new_account, None).await;

    match result{
        Ok(_) => HttpResponse::Created().json(json!({
            "id": new_account.id,
            "name": new_account.name,
            "email": new_account.email,
        })),
        Err(e)=> {
            eprintln!("Account creation failed: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }

}

async fn sign_in(db: web::Data<Collection<models::User>> , data : web::Json<models::SignInInput>)-> impl Responder{
    let filter = doc!{ "email" :&data.email };
    let user = db.find_one(filter, None).await;

    match user{
        Ok(Some(user)) => {
            if argon2::verify_encoded(&user.password, data.password.as_bytes()).unwrap_or(false) {
                // Create JWT claims with an expiration time (1 hour)
                let expiration = chrono::Utc::now()
                    .checked_add_signed(chrono::Duration::hours(1))
                    .expect("valid timestamp")
                    .timestamp() as usize;
                
                let claims = models::Claims {
                    sub: user.id.clone(),
                    exp: expiration,
                };
                
                // Retrieve the JWT secret from environment variables
                let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                
                // Encode the JWT
                let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("Failed to encode token: {}", e);
                        return HttpResponse::InternalServerError().json("Internal Server Error");
                    }
                };
                
                // Respond with the JWT
                HttpResponse::Ok().json(models::AuthResponse { token })
            } else {
                // Password mismatch
                HttpResponse::Unauthorized().json("Invalid credentials")
            }
        },
        Ok(None) => {
            // User not found
            HttpResponse::Unauthorized().json("Invalid credentials")
        },
        Err(e) => {
            // Database error
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }

}

async fn get_profile(db: web::Data<Collection<models::User>> , email : web::Path<String>) -> impl Responder{
    let filter = doc!{ "email" : &email.into_inner()};
    let user = db.find_one(filter, None).await;
    match user{
        Ok(Some(user))=>{
            let resp = json!({
                "id": user.id,
                "name": user.name,
                "email": user.email,
            });
            HttpResponse::Ok().json(resp)
        },
        Ok(None)=> HttpResponse::NotFound().json("User profile not found"),
        Err(e) => {
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }

    }
}

async fn update_profile(db: web::Data<Collection<models::User>>, email : web::Path<String >, data : web::Json<models::SignUpInput> , req : HttpRequest) -> impl Responder{
    let user_id = req.extensions().get::<String>().cloned();
    let filter = doc!{"email": &email.into_inner(),"id" : user_id};
    let salt :[u8 ; 16] = rand::thread_rng().gen();
    let config = ArgonConfig::default();

    let hashed_password = match argon2::hash_encoded(data.password.as_bytes(), &salt, &config){
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Failed to hash password: {}", e);
            return HttpResponse::InternalServerError().json("Internal Server Error");
        }
    };
    let new_val = doc!{
            "$set":{
                "name": data.name.clone(),
                "password": hashed_password,
            }
    };

    match db.find_one_and_update(filter, new_val, None).await{
        Ok(Some(_user)) => {
            HttpResponse::Ok().json("Profile updated successfully")
        }
        Ok(None) => {
            HttpResponse::NotFound().json("User not found")
        },
        Err(e) => {
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }

}

async fn delete_profile(db: web::Data<Collection<models::User>> , email : web::Path<String>, req : HttpRequest)-> impl Responder{
    let user_id = req.extensions().get::<String>().cloned();

    let filter = doc!{"email": &email.into_inner() ,"id" : user_id};
    match db.delete_one(filter, None).await {
        Ok(result) if result.deleted_count == 1 => {
            HttpResponse::Ok().json("Profile deleted successfully")
        }
        Ok(_) => HttpResponse::NotFound().json("Profile not found"),
        Err(e) => {
            eprintln!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Internal Server Error")
        }
    }

}

async fn get_id(db: web::Data<Collection<models::Counter>> , seq_name: &str) -> Result<i64 , mongodb::error::Error>{

    let filter = doc! {"_id": seq_name};
    let update = doc! {"$inc": {"seq_name": 1}};

    let options = mongodb::options::FindOneAndUpdateOptions::builder()
    .upsert(true).return_document(mongodb::options::ReturnDocument::After)
    .build();

    let result = db.find_one_and_update(filter , update , options).await?;

    if let Some(counter) = result {
        Ok(counter.seq)
    }
    else {
        Err(mongodb::error::Error::custom("Failed to generate sequence value"))
    }

}

async fn add_product(db : web::Data<Collection<models::Product>> , data : web::Json<Product> , counter : web::Data<Collection<models::Counter>>,req : HttpRequest)-> Result<HttpResponse , Error>{

    let next_id = get_id(counter, "Product").await.map_err(actix_web::error::ErrorInternalServerError)?;
    let user_id_g = req.extensions().get::<String>().cloned();

    if let Some(user_id) = user_id_g{
        let product = models::Product{
            _id: next_id,
            user_id: user_id,
            name: data.name.clone(),
            price: data.price,
            description: data.description.clone(),
            category: data.category.clone(),
        };
        let result = db.insert_one(product.clone(), None).await;
        match result {
        Ok(_) => Ok(HttpResponse::Created().json(product)),
        Err(e) => {
            eprintln!("Failed to insert product: {}", e);
            Ok(HttpResponse::InternalServerError().json("Internal Server Error"))
            }
        }

    }
    else {
        Ok(HttpResponse::Unauthorized().json("Login required"))
    }
    
}

async fn get_product(db : web::Data<Collection<models::Product>>, name:web::Path<String>)->Result<HttpResponse>{
    let filter = doc!{"name": &name.into_inner()};
    match db.find_one(filter, None).await{
        Ok(Some(product)) => Ok(HttpResponse::Ok().json(product)),
        Ok(None) => Ok(HttpResponse::NotFound().json("Product not found")),
        Err(e) => {
            eprintln!("Database error: {}", e);
            Ok(HttpResponse::InternalServerError().json("Internal Server Error"))
        }
    }

}

async fn get_products_by_cat(db : web::Data<Collection<models::Product>>, category:web::Path<String>)->Result<HttpResponse, Error>{

    let filter = doc!{"category": &category.into_inner()};
    let mut products =vec![];
    let mut cursor = db.find(filter, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
    while let Some(result) = cursor.next().await{
        match result{
            Ok(product) => products.push(product),
            Err(e) => {
                eprintln!("Database error: {}", e);
                return Ok(HttpResponse::InternalServerError().json("Internal Server Error"));
            }
        }
    }
    Ok(HttpResponse::Ok().json(products))

}

async fn update_product(db: web::Data<Collection<Product>> ,req: HttpRequest, product_id: web::Path<i64> , new_value: web::Json<Product>) -> Result <HttpResponse , Error>{

        let user_id_g = req.extensions().get::<String>().cloned();
        if let Some(user_id) = user_id_g{

            let filter = doc!{"_id": product_id.into_inner(), "user_id": user_id};
            let update =doc! {"$set":{
                "name": new_value.name.clone(),
                "price": new_value.price,
                "description": new_value.description.clone(),
                "category": new_value.category.clone(),
            }};
            let result = db.update_one(filter, update, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
            if result.modified_count == 1 {
                Ok(HttpResponse::Ok().json("Product updated successfully"))
            }
            else{
                Ok(HttpResponse::NotFound().json("Product not found or not owned by the user"))
            }

        }
        else{
            Ok(HttpResponse::Unauthorized().json("Login required"))
        }

    }

async fn delete_product(db: web::Data<Collection<Product>> ,req: HttpRequest, product_id: web::Path<i64>)-> Result <HttpResponse , Error>{

    let user_id_g= req.extensions().get::<String>().cloned();
    if let Some(user_id) = user_id_g{

            let filter = doc!{"_id": product_id.into_inner(), "user_id": user_id};
            let result = db.delete_one(filter, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
            if result.deleted_count == 1 {
                Ok(HttpResponse::Ok().json("Product deleted successfully"))
            }
            else{
                Ok(HttpResponse::NotFound().json("Product not found or not owned by the user"))
            }

        }
        else{
            Ok(HttpResponse::Unauthorized().json("Login required"))
        }
    }
async fn add_to_cart(db: web::Data<Collection<models::Cart>> , data: web::Json<models::Cart>, req : HttpRequest)-> Result<HttpResponse>{

    let user_id_g = req.extensions().get::<String>().cloned();
    if let Some(user_id) = user_id_g{

        let cart_item = models::Cart{
            user_id: user_id,
            product_id: data.product_id,
            quantity: data.quantity,
        };
        let result = db.insert_one(cart_item, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
        if result.inserted_id.as_object_id().is_some() {
            Ok(HttpResponse::Created().json("Product added to cart successfully"))
        }
        else{
            Ok(HttpResponse::InternalServerError().json("Failed to add product to cart"))
        }

    }
    else {
        Ok(HttpResponse::Unauthorized().json("Login required"))
    }

}

async fn remove_from_cart(db: web::Data<Collection<models::Cart>> , product_id: web::Path<i64>, req : HttpRequest)-> Result<HttpResponse>{

    let user_id_g = req.extensions().get::<String>().cloned();
    if let Some(user_id) = user_id_g{

        let filter = doc! {
            "user_id": user_id,
            "product_id": product_id.into_inner(),
        };
        let result = db.delete_one(filter, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
        if result.deleted_count == 1 {
            Ok(HttpResponse::Ok().json("Product removed from cart successfully"))
        }
        else{
            Ok(HttpResponse::NotFound().json("Product not found in cart or not owned by the user"))
        }

    }
    else {
        Ok(HttpResponse::Unauthorized().json("Login required"))
    }

}

async fn add_to_wishlist(db: web::Data<Collection<models::Wishlist>> , data: web::Json<models::Wishlist>, req : HttpRequest)-> Result<HttpResponse>{

    let user_id_g = req.extensions().get::<String>().cloned();
    if let Some(user_id) = user_id_g{

        let wishlist_item = models::Wishlist{
            user_id: user_id,
            product_id: data.product_id,
        };
        let result = db.insert_one(wishlist_item, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
        if result.inserted_id.as_object_id().is_some() {
            Ok(HttpResponse::Created().json("Product added to wishlist successfully"))
        }
        else{
            Ok(HttpResponse::InternalServerError().json("Failed to add product to wishlist"))
        }

    }
    else {
        Ok(HttpResponse::Unauthorized().json("Login required"))
    }

}

async fn remove_from_wishlist(db: web::Data<Collection<models::Wishlist>> , product_id: web::Path<i64>, req : HttpRequest)-> Result<HttpResponse>{

    let user_id_g = req.extensions().get::<String>().cloned();
    if let Some(user_id) = user_id_g{

        let filter = doc! {
            "user_id": user_id,
            "product_id": product_id.into_inner(),
        };
        let result = db.delete_one(filter, None).await.map_err(actix_web::error::ErrorInternalServerError)?;
        if result.deleted_count == 1 {
            Ok(HttpResponse::Ok().json("Product removed from wishlist successfully"))
        }
        else{
            Ok(HttpResponse::NotFound().json("Product not found in wishlist or not owned by the user"))
        }

    }
    else {
        Ok(HttpResponse::Unauthorized().json("Login required"))
    }

}



#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok(); // Load environment variables from .env file
    env_logger::init(); // Initialize the logger
    
    // Connect to the MongoDB database
    let db = db::connect().await;
    
    // Retrieve the JWT secret from environment variables
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    
    // Start the Actix-web HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone())) // Share the database connection with handlers
            // Define public routes
            .route("/signup", web::post().to(sign_up))
            .route("/signin", web::post().to(sign_in))
            .service(
                web::scope("")
                    .wrap(middleware::AuthMiddleware::new(jwt_secret.clone()))
                    .route("/profile/{email}", web::get().to(get_profile))
                    .route("/profile/{email}", web::put().to(update_profile))
                    .route("/delete/{email}", web::delete().to(delete_profile))
                    .route("/add_product" , web::post().to(add_product))
                    .route("/product/{name}", web::get().to(get_product))
                    .route("/products/{category}", web::get().to(get_products_by_cat))
                    .route("/update_products/{product_id}", web::put().to(update_product))
                    .route("delete_products/{product_id}", web::delete().to(delete_product))
                    .route("/add_to_cart", web::post().to(add_to_cart))
                    .route("/remove_from_cart/{product_id}", web::delete().to(remove_from_cart))
                    .route("/add_to_wishlist", web::post().to(add_to_wishlist))
                    .route("/remove_from_wishlist/{product_id}", web::delete().to(remove_from_wishlist))
            )
    })
    .bind("127.0.0.1:8080")? // Bind the server to localhost on port 8080
    .run() // Run the server
    .await
}
