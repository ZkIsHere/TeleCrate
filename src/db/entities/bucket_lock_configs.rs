//! Entity `bucket_lock_configs` — mirror `migrations/0003_*.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "bucket_lock_configs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket: String,
    pub status: String,
    pub default_retention_mode: Option<String>,
    pub default_retention_days: Option<i64>,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
