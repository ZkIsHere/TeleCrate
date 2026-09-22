//! Entity `multipart_parts` — mirror `migrations/0002_*.sql`.
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "multipart_parts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub upload_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub part_number: i64,
    pub size: i64,
    pub etag: String,
    pub plaintext_sha256: String,
    pub ciphertext_sha256: String,
    pub spool_path: Option<String>,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::multipart_uploads::Entity",
        from = "Column::UploadId",
        to = "super::multipart_uploads::Column::UploadId"
    )]
    Uploads,
}

impl ActiveModelBehavior for ActiveModel {}
