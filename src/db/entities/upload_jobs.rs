//! Entity `upload_jobs` — mirror `migrations/0001_init.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "upload_jobs")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub job_id: String,
    pub version_id: String,
    pub state: String,
    pub lease_owner: Option<String>,
    pub lease_expires: Option<String>,
    pub retry_count: i64,
    pub next_attempt: String,
    pub generation: i64,
    pub last_error: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
