//! Entity `objects` — mirror `0001_init.sql` + 0002 (2 cột metadata).
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "objects")]
pub struct Model {
    pub bucket: String,
    pub key: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: String,
    pub is_delete_marker: i64,
    pub storage_state: String,
    pub size: i64,
    pub etag: String,
    pub content_type: String,
    pub created_at: String,
    pub user_metadata_json: Option<String>,
    pub system_metadata_json: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
