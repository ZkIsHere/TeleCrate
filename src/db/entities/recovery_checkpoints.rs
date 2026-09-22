//! Entity `recovery_checkpoints` — mirror `migrations/0001_init.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "recovery_checkpoints")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub seq: i64,
    pub manifest_json: String,
    pub sha256: String,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
