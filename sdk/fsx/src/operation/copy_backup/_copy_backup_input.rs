// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopyBackupInput {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the source backup. Specifies the ID of the backup that's being copied.</p>
    pub source_backup_id: ::std::option::Option<::std::string::String>,
    /// <p>The source Amazon Web Services Region of the backup. Specifies the Amazon Web Services Region from which the backup is being copied. The source and destination Regions must be in the same Amazon Web Services partition. If you don't specify a Region, <code>SourceRegion</code> defaults to the Region where the request is sent from (in-Region copy).</p>
    pub source_region: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ID of the Key Management Service (KMS) key to use for encrypting data on Amazon FSx file systems, as follows:</p>
    /// <ul>
    /// <li>
    /// <p>Amazon FSx for Lustre <code>PERSISTENT_1</code> and <code>PERSISTENT_2</code> deployment types only.</p>
    /// <p><code>SCRATCH_1</code> and <code>SCRATCH_2</code> types are encrypted using the Amazon FSx service KMS key for your account.</p></li>
    /// <li>
    /// <p>Amazon FSx for NetApp ONTAP</p></li>
    /// <li>
    /// <p>Amazon FSx for OpenZFS</p></li>
    /// <li>
    /// <p>Amazon FSx for Windows File Server</p></li>
    /// </ul>
    /// <p>If a <code>KmsKeyId</code> isn't specified, the Amazon FSx-managed KMS key for your account is used. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html">Encrypt</a> in the <i>Key Management Service API Reference</i>.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>A Boolean flag indicating whether tags from the source backup should be copied to the backup copy. This value defaults to <code>false</code>.</p>
    /// <p>If you set <code>CopyTags</code> to <code>true</code> and the source backup has existing tags, you can use the <code>Tags</code> parameter to create new tags, provided that the sum of the source backup tags and the new tags doesn't exceed 50. Both sets of tags are merged. If there are tag conflicts (for example, two tags with the same key but different values), the tags created with the <code>Tags</code> parameter take precedence.</p>
    pub copy_tags: ::std::option::Option<bool>,
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CopyBackupInput {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The ID of the source backup. Specifies the ID of the backup that's being copied.</p>
    pub fn source_backup_id(&self) -> ::std::option::Option<&str> {
        self.source_backup_id.as_deref()
    }
    /// <p>The source Amazon Web Services Region of the backup. Specifies the Amazon Web Services Region from which the backup is being copied. The source and destination Regions must be in the same Amazon Web Services partition. If you don't specify a Region, <code>SourceRegion</code> defaults to the Region where the request is sent from (in-Region copy).</p>
    pub fn source_region(&self) -> ::std::option::Option<&str> {
        self.source_region.as_deref()
    }
    /// <p>Specifies the ID of the Key Management Service (KMS) key to use for encrypting data on Amazon FSx file systems, as follows:</p>
    /// <ul>
    /// <li>
    /// <p>Amazon FSx for Lustre <code>PERSISTENT_1</code> and <code>PERSISTENT_2</code> deployment types only.</p>
    /// <p><code>SCRATCH_1</code> and <code>SCRATCH_2</code> types are encrypted using the Amazon FSx service KMS key for your account.</p></li>
    /// <li>
    /// <p>Amazon FSx for NetApp ONTAP</p></li>
    /// <li>
    /// <p>Amazon FSx for OpenZFS</p></li>
    /// <li>
    /// <p>Amazon FSx for Windows File Server</p></li>
    /// </ul>
    /// <p>If a <code>KmsKeyId</code> isn't specified, the Amazon FSx-managed KMS key for your account is used. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html">Encrypt</a> in the <i>Key Management Service API Reference</i>.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>A Boolean flag indicating whether tags from the source backup should be copied to the backup copy. This value defaults to <code>false</code>.</p>
    /// <p>If you set <code>CopyTags</code> to <code>true</code> and the source backup has existing tags, you can use the <code>Tags</code> parameter to create new tags, provided that the sum of the source backup tags and the new tags doesn't exceed 50. Both sets of tags are merged. If there are tag conflicts (for example, two tags with the same key but different values), the tags created with the <code>Tags</code> parameter take precedence.</p>
    pub fn copy_tags(&self) -> ::std::option::Option<bool> {
        self.copy_tags
    }
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CopyBackupInput {
    /// Creates a new builder-style object to manufacture [`CopyBackupInput`](crate::operation::copy_backup::CopyBackupInput).
    pub fn builder() -> crate::operation::copy_backup::builders::CopyBackupInputBuilder {
        crate::operation::copy_backup::builders::CopyBackupInputBuilder::default()
    }
}

/// A builder for [`CopyBackupInput`](crate::operation::copy_backup::CopyBackupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopyBackupInputBuilder {
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) source_backup_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_region: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) copy_tags: ::std::option::Option<bool>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CopyBackupInputBuilder {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The ID of the source backup. Specifies the ID of the backup that's being copied.</p>
    /// This field is required.
    pub fn source_backup_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_backup_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the source backup. Specifies the ID of the backup that's being copied.</p>
    pub fn set_source_backup_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_backup_id = input;
        self
    }
    /// <p>The ID of the source backup. Specifies the ID of the backup that's being copied.</p>
    pub fn get_source_backup_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_backup_id
    }
    /// <p>The source Amazon Web Services Region of the backup. Specifies the Amazon Web Services Region from which the backup is being copied. The source and destination Regions must be in the same Amazon Web Services partition. If you don't specify a Region, <code>SourceRegion</code> defaults to the Region where the request is sent from (in-Region copy).</p>
    pub fn source_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The source Amazon Web Services Region of the backup. Specifies the Amazon Web Services Region from which the backup is being copied. The source and destination Regions must be in the same Amazon Web Services partition. If you don't specify a Region, <code>SourceRegion</code> defaults to the Region where the request is sent from (in-Region copy).</p>
    pub fn set_source_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_region = input;
        self
    }
    /// <p>The source Amazon Web Services Region of the backup. Specifies the Amazon Web Services Region from which the backup is being copied. The source and destination Regions must be in the same Amazon Web Services partition. If you don't specify a Region, <code>SourceRegion</code> defaults to the Region where the request is sent from (in-Region copy).</p>
    pub fn get_source_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_region
    }
    /// <p>Specifies the ID of the Key Management Service (KMS) key to use for encrypting data on Amazon FSx file systems, as follows:</p>
    /// <ul>
    /// <li>
    /// <p>Amazon FSx for Lustre <code>PERSISTENT_1</code> and <code>PERSISTENT_2</code> deployment types only.</p>
    /// <p><code>SCRATCH_1</code> and <code>SCRATCH_2</code> types are encrypted using the Amazon FSx service KMS key for your account.</p></li>
    /// <li>
    /// <p>Amazon FSx for NetApp ONTAP</p></li>
    /// <li>
    /// <p>Amazon FSx for OpenZFS</p></li>
    /// <li>
    /// <p>Amazon FSx for Windows File Server</p></li>
    /// </ul>
    /// <p>If a <code>KmsKeyId</code> isn't specified, the Amazon FSx-managed KMS key for your account is used. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html">Encrypt</a> in the <i>Key Management Service API Reference</i>.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the Key Management Service (KMS) key to use for encrypting data on Amazon FSx file systems, as follows:</p>
    /// <ul>
    /// <li>
    /// <p>Amazon FSx for Lustre <code>PERSISTENT_1</code> and <code>PERSISTENT_2</code> deployment types only.</p>
    /// <p><code>SCRATCH_1</code> and <code>SCRATCH_2</code> types are encrypted using the Amazon FSx service KMS key for your account.</p></li>
    /// <li>
    /// <p>Amazon FSx for NetApp ONTAP</p></li>
    /// <li>
    /// <p>Amazon FSx for OpenZFS</p></li>
    /// <li>
    /// <p>Amazon FSx for Windows File Server</p></li>
    /// </ul>
    /// <p>If a <code>KmsKeyId</code> isn't specified, the Amazon FSx-managed KMS key for your account is used. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html">Encrypt</a> in the <i>Key Management Service API Reference</i>.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>Specifies the ID of the Key Management Service (KMS) key to use for encrypting data on Amazon FSx file systems, as follows:</p>
    /// <ul>
    /// <li>
    /// <p>Amazon FSx for Lustre <code>PERSISTENT_1</code> and <code>PERSISTENT_2</code> deployment types only.</p>
    /// <p><code>SCRATCH_1</code> and <code>SCRATCH_2</code> types are encrypted using the Amazon FSx service KMS key for your account.</p></li>
    /// <li>
    /// <p>Amazon FSx for NetApp ONTAP</p></li>
    /// <li>
    /// <p>Amazon FSx for OpenZFS</p></li>
    /// <li>
    /// <p>Amazon FSx for Windows File Server</p></li>
    /// </ul>
    /// <p>If a <code>KmsKeyId</code> isn't specified, the Amazon FSx-managed KMS key for your account is used. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html">Encrypt</a> in the <i>Key Management Service API Reference</i>.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>A Boolean flag indicating whether tags from the source backup should be copied to the backup copy. This value defaults to <code>false</code>.</p>
    /// <p>If you set <code>CopyTags</code> to <code>true</code> and the source backup has existing tags, you can use the <code>Tags</code> parameter to create new tags, provided that the sum of the source backup tags and the new tags doesn't exceed 50. Both sets of tags are merged. If there are tag conflicts (for example, two tags with the same key but different values), the tags created with the <code>Tags</code> parameter take precedence.</p>
    pub fn copy_tags(mut self, input: bool) -> Self {
        self.copy_tags = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean flag indicating whether tags from the source backup should be copied to the backup copy. This value defaults to <code>false</code>.</p>
    /// <p>If you set <code>CopyTags</code> to <code>true</code> and the source backup has existing tags, you can use the <code>Tags</code> parameter to create new tags, provided that the sum of the source backup tags and the new tags doesn't exceed 50. Both sets of tags are merged. If there are tag conflicts (for example, two tags with the same key but different values), the tags created with the <code>Tags</code> parameter take precedence.</p>
    pub fn set_copy_tags(mut self, input: ::std::option::Option<bool>) -> Self {
        self.copy_tags = input;
        self
    }
    /// <p>A Boolean flag indicating whether tags from the source backup should be copied to the backup copy. This value defaults to <code>false</code>.</p>
    /// <p>If you set <code>CopyTags</code> to <code>true</code> and the source backup has existing tags, you can use the <code>Tags</code> parameter to create new tags, provided that the sum of the source backup tags and the new tags doesn't exceed 50. Both sets of tags are merged. If there are tag conflicts (for example, two tags with the same key but different values), the tags created with the <code>Tags</code> parameter take precedence.</p>
    pub fn get_copy_tags(&self) -> &::std::option::Option<bool> {
        &self.copy_tags
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of <code>Tag</code> values, with a maximum of 50 elements.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CopyBackupInput`](crate::operation::copy_backup::CopyBackupInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::copy_backup::CopyBackupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::copy_backup::CopyBackupInput {
            client_request_token: self.client_request_token,
            source_backup_id: self.source_backup_id,
            source_region: self.source_region,
            kms_key_id: self.kms_key_id,
            copy_tags: self.copy_tags,
            tags: self.tags,
        })
    }
}
