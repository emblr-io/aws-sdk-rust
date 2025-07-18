// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>CopySnapshotMessage</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopySnapshotInput {
    /// <p>The name of an existing snapshot from which to make a copy.</p>
    pub source_snapshot_name: ::std::option::Option<::std::string::String>,
    /// <p>A name for the snapshot copy. ElastiCache does not permit overwriting a snapshot, therefore this name must be unique within its context - ElastiCache or an Amazon S3 bucket if exporting.</p>
    pub target_snapshot_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 bucket to which the snapshot is exported. This parameter is used only when exporting a snapshot for external access.</p>
    /// <p>When using this parameter to export a snapshot, be sure Amazon ElastiCache has the needed permissions to this S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html#backups-exporting-grant-access">Step 2: Grant ElastiCache Access to Your Amazon S3 Bucket</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html">Exporting a Snapshot</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    pub target_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the KMS key used to encrypt the target snapshot.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CopySnapshotInput {
    /// <p>The name of an existing snapshot from which to make a copy.</p>
    pub fn source_snapshot_name(&self) -> ::std::option::Option<&str> {
        self.source_snapshot_name.as_deref()
    }
    /// <p>A name for the snapshot copy. ElastiCache does not permit overwriting a snapshot, therefore this name must be unique within its context - ElastiCache or an Amazon S3 bucket if exporting.</p>
    pub fn target_snapshot_name(&self) -> ::std::option::Option<&str> {
        self.target_snapshot_name.as_deref()
    }
    /// <p>The Amazon S3 bucket to which the snapshot is exported. This parameter is used only when exporting a snapshot for external access.</p>
    /// <p>When using this parameter to export a snapshot, be sure Amazon ElastiCache has the needed permissions to this S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html#backups-exporting-grant-access">Step 2: Grant ElastiCache Access to Your Amazon S3 Bucket</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html">Exporting a Snapshot</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    pub fn target_bucket(&self) -> ::std::option::Option<&str> {
        self.target_bucket.as_deref()
    }
    /// <p>The ID of the KMS key used to encrypt the target snapshot.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CopySnapshotInput {
    /// Creates a new builder-style object to manufacture [`CopySnapshotInput`](crate::operation::copy_snapshot::CopySnapshotInput).
    pub fn builder() -> crate::operation::copy_snapshot::builders::CopySnapshotInputBuilder {
        crate::operation::copy_snapshot::builders::CopySnapshotInputBuilder::default()
    }
}

/// A builder for [`CopySnapshotInput`](crate::operation::copy_snapshot::CopySnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopySnapshotInputBuilder {
    pub(crate) source_snapshot_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_snapshot_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CopySnapshotInputBuilder {
    /// <p>The name of an existing snapshot from which to make a copy.</p>
    /// This field is required.
    pub fn source_snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an existing snapshot from which to make a copy.</p>
    pub fn set_source_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_snapshot_name = input;
        self
    }
    /// <p>The name of an existing snapshot from which to make a copy.</p>
    pub fn get_source_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_snapshot_name
    }
    /// <p>A name for the snapshot copy. ElastiCache does not permit overwriting a snapshot, therefore this name must be unique within its context - ElastiCache or an Amazon S3 bucket if exporting.</p>
    /// This field is required.
    pub fn target_snapshot_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_snapshot_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the snapshot copy. ElastiCache does not permit overwriting a snapshot, therefore this name must be unique within its context - ElastiCache or an Amazon S3 bucket if exporting.</p>
    pub fn set_target_snapshot_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_snapshot_name = input;
        self
    }
    /// <p>A name for the snapshot copy. ElastiCache does not permit overwriting a snapshot, therefore this name must be unique within its context - ElastiCache or an Amazon S3 bucket if exporting.</p>
    pub fn get_target_snapshot_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_snapshot_name
    }
    /// <p>The Amazon S3 bucket to which the snapshot is exported. This parameter is used only when exporting a snapshot for external access.</p>
    /// <p>When using this parameter to export a snapshot, be sure Amazon ElastiCache has the needed permissions to this S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html#backups-exporting-grant-access">Step 2: Grant ElastiCache Access to Your Amazon S3 Bucket</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html">Exporting a Snapshot</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    pub fn target_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 bucket to which the snapshot is exported. This parameter is used only when exporting a snapshot for external access.</p>
    /// <p>When using this parameter to export a snapshot, be sure Amazon ElastiCache has the needed permissions to this S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html#backups-exporting-grant-access">Step 2: Grant ElastiCache Access to Your Amazon S3 Bucket</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html">Exporting a Snapshot</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    pub fn set_target_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_bucket = input;
        self
    }
    /// <p>The Amazon S3 bucket to which the snapshot is exported. This parameter is used only when exporting a snapshot for external access.</p>
    /// <p>When using this parameter to export a snapshot, be sure Amazon ElastiCache has the needed permissions to this S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html#backups-exporting-grant-access">Step 2: Grant ElastiCache Access to Your Amazon S3 Bucket</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/backups-exporting.html">Exporting a Snapshot</a> in the <i>Amazon ElastiCache User Guide</i>.</p>
    pub fn get_target_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_bucket
    }
    /// <p>The ID of the KMS key used to encrypt the target snapshot.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the KMS key used to encrypt the target snapshot.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The ID of the KMS key used to encrypt the target snapshot.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CopySnapshotInput`](crate::operation::copy_snapshot::CopySnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::copy_snapshot::CopySnapshotInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::copy_snapshot::CopySnapshotInput {
            source_snapshot_name: self.source_snapshot_name,
            target_snapshot_name: self.target_snapshot_name,
            target_bucket: self.target_bucket,
            kms_key_id: self.kms_key_id,
            tags: self.tags,
        })
    }
}
