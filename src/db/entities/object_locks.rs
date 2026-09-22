//! Entity `object_locks` — mirror `migrations/0003_*.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "object_locks")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: String,
    pub retain_until_date: Option<String>,
    pub mode: Option<String>,
    pub legal_hold: i64,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
