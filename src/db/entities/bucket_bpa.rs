//! Entity `bucket_bpa` — mirror `migrations/0003_*.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "bucket_bpa")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket: String,
    pub block_public_acls: i64,
    pub ignore_public_acls: i64,
    pub block_public_policy: i64,
    pub restrict_public_buckets: i64,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
