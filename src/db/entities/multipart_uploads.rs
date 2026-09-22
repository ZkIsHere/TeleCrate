//! Entity `multipart_uploads` — mirror `migrations/0002_*.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "multipart_uploads")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub content_type: String,
    pub metadata_json: Option<String>,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
