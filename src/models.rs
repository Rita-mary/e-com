use serde::{Serialize, Deserialize};

#[derive(Debug , Serialize, Deserialize)]
pub struct User{
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug , Serialize, Deserialize)]
pub struct SignUpInput{
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug , Serialize, Deserialize)]
pub struct SignInInput{
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user ID)
    pub exp: usize,  // Expiration time as UTC timestamp
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize , Deserialize, Debug)]
pub struct Counter{
    pub _id : String,
    pub seq :  i64,
}

#[derive(Serialize , Deserialize, Debug, Clone)]
pub struct Product {
    pub _id: i64,
    pub user_id : String,
    pub name: String,
    pub price: f64,
    pub description: Option<String>,
    pub category: String,
}