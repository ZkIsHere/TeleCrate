//! Entity `access_keys` — mirror 0003 + 0004 (2 cột dashboard).
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "access_keys")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub access_key_id: String,
    pub secret_key: String,
    pub status: String,
    pub description: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub allowed_buckets: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
