// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StartSnapshotOutput {
    /// <p>The description of the snapshot.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the snapshot.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID of the snapshot owner.</p>
    pub owner_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the snapshot.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>The timestamp when the snapshot was created.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The size of the volume, in GiB.</p>
    pub volume_size: ::std::option::Option<i64>,
    /// <p>The size of the blocks in the snapshot, in bytes.</p>
    pub block_size: ::std::option::Option<i32>,
    /// <p>The tags applied to the snapshot. You can specify up to 50 tags per snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"> Tagging your Amazon EC2 resources</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The ID of the parent snapshot.</p>
    pub parent_snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key used to encrypt the snapshot.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>Reserved for future use.</p>
    pub sse_type: ::std::option::Option<crate::types::SseType>,
    _request_id: Option<String>,
}
impl StartSnapshotOutput {
    /// <p>The description of the snapshot.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ID of the snapshot.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
    /// <p>The Amazon Web Services account ID of the snapshot owner.</p>
    pub fn owner_id(&self) -> ::std::option::Option<&str> {
        self.owner_id.as_deref()
    }
    /// <p>The status of the snapshot.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>The timestamp when the snapshot was created.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn volume_size(&self) -> ::std::option::Option<i64> {
        self.volume_size
    }
    /// <p>The size of the blocks in the snapshot, in bytes.</p>
    pub fn block_size(&self) -> ::std::option::Option<i32> {
        self.block_size
    }
    /// <p>The tags applied to the snapshot. You can specify up to 50 tags per snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"> Tagging your Amazon EC2 resources</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the parent snapshot.</p>
    pub fn parent_snapshot_id(&self) -> ::std::option::Option<&str> {
        self.parent_snapshot_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key used to encrypt the snapshot.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>Reserved for future use.</p>
    pub fn sse_type(&self) -> ::std::option::Option<&crate::types::SseType> {
        self.sse_type.as_ref()
    }
}
impl ::std::fmt::Debug for StartSnapshotOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartSnapshotOutput");
        formatter.field("description", &self.description);
        formatter.field("snapshot_id", &self.snapshot_id);
        formatter.field("owner_id", &self.owner_id);
        formatter.field("status", &self.status);
        formatter.field("start_time", &self.start_time);
        formatter.field("volume_size", &self.volume_size);
        formatter.field("block_size", &self.block_size);
        formatter.field("tags", &self.tags);
        formatter.field("parent_snapshot_id", &self.parent_snapshot_id);
        formatter.field("kms_key_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("sse_type", &self.sse_type);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for StartSnapshotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartSnapshotOutput {
    /// Creates a new builder-style object to manufacture [`StartSnapshotOutput`](crate::operation::start_snapshot::StartSnapshotOutput).
    pub fn builder() -> crate::operation::start_snapshot::builders::StartSnapshotOutputBuilder {
        crate::operation::start_snapshot::builders::StartSnapshotOutputBuilder::default()
    }
}

/// A builder for [`StartSnapshotOutput`](crate::operation::start_snapshot::StartSnapshotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StartSnapshotOutputBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) owner_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) volume_size: ::std::option::Option<i64>,
    pub(crate) block_size: ::std::option::Option<i32>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) parent_snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sse_type: ::std::option::Option<crate::types::SseType>,
    _request_id: Option<String>,
}
impl StartSnapshotOutputBuilder {
    /// <p>The description of the snapshot.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the snapshot.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the snapshot.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ID of the snapshot.</p>
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the snapshot.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>The ID of the snapshot.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    /// <p>The Amazon Web Services account ID of the snapshot owner.</p>
    pub fn owner_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the snapshot owner.</p>
    pub fn set_owner_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the snapshot owner.</p>
    pub fn get_owner_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_id
    }
    /// <p>The status of the snapshot.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the snapshot.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the snapshot.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>The timestamp when the snapshot was created.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the snapshot was created.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The timestamp when the snapshot was created.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn volume_size(mut self, input: i64) -> Self {
        self.volume_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn set_volume_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.volume_size = input;
        self
    }
    /// <p>The size of the volume, in GiB.</p>
    pub fn get_volume_size(&self) -> &::std::option::Option<i64> {
        &self.volume_size
    }
    /// <p>The size of the blocks in the snapshot, in bytes.</p>
    pub fn block_size(mut self, input: i32) -> Self {
        self.block_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the blocks in the snapshot, in bytes.</p>
    pub fn set_block_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.block_size = input;
        self
    }
    /// <p>The size of the blocks in the snapshot, in bytes.</p>
    pub fn get_block_size(&self) -> &::std::option::Option<i32> {
        &self.block_size
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags applied to the snapshot. You can specify up to 50 tags per snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"> Tagging your Amazon EC2 resources</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags applied to the snapshot. You can specify up to 50 tags per snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"> Tagging your Amazon EC2 resources</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags applied to the snapshot. You can specify up to 50 tags per snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"> Tagging your Amazon EC2 resources</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The ID of the parent snapshot.</p>
    pub fn parent_snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the parent snapshot.</p>
    pub fn set_parent_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_snapshot_id = input;
        self
    }
    /// <p>The ID of the parent snapshot.</p>
    pub fn get_parent_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_snapshot_id
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key used to encrypt the snapshot.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key used to encrypt the snapshot.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key used to encrypt the snapshot.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// <p>Reserved for future use.</p>
    pub fn sse_type(mut self, input: crate::types::SseType) -> Self {
        self.sse_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reserved for future use.</p>
    pub fn set_sse_type(mut self, input: ::std::option::Option<crate::types::SseType>) -> Self {
        self.sse_type = input;
        self
    }
    /// <p>Reserved for future use.</p>
    pub fn get_sse_type(&self) -> &::std::option::Option<crate::types::SseType> {
        &self.sse_type
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartSnapshotOutput`](crate::operation::start_snapshot::StartSnapshotOutput).
    pub fn build(self) -> crate::operation::start_snapshot::StartSnapshotOutput {
        crate::operation::start_snapshot::StartSnapshotOutput {
            description: self.description,
            snapshot_id: self.snapshot_id,
            owner_id: self.owner_id,
            status: self.status,
            start_time: self.start_time,
            volume_size: self.volume_size,
            block_size: self.block_size,
            tags: self.tags,
            parent_snapshot_id: self.parent_snapshot_id,
            kms_key_arn: self.kms_key_arn,
            sse_type: self.sse_type,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for StartSnapshotOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartSnapshotOutputBuilder");
        formatter.field("description", &self.description);
        formatter.field("snapshot_id", &self.snapshot_id);
        formatter.field("owner_id", &self.owner_id);
        formatter.field("status", &self.status);
        formatter.field("start_time", &self.start_time);
        formatter.field("volume_size", &self.volume_size);
        formatter.field("block_size", &self.block_size);
        formatter.field("tags", &self.tags);
        formatter.field("parent_snapshot_id", &self.parent_snapshot_id);
        formatter.field("kms_key_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("sse_type", &self.sse_type);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
