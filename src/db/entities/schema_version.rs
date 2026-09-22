//! Entity `schema_version` — mirror `migrations/0001_init.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "schema_version")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub version: i64,
    pub applied_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
