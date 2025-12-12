use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {message}")]
    Config { message: String },

    #[error("Internal error: {message}")]
    Internal { message: String },
}
