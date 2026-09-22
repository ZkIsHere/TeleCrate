//! Entity `bucket_policies` — mirror `migrations/0003_*.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "bucket_policies")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket: String,
    pub policy_json: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
