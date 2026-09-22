//! Entity `chunks` — mirror `migrations/0001_init.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "chunks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub idx: i64,
    pub offset: i64,
    pub length: i64,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub encryption_mode: String,
    pub key_ref: Option<String>,
    pub nonce: Option<String>,
    pub spool_path: Option<String>,
    pub remote_locator_json: Option<String>,
    pub state: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
