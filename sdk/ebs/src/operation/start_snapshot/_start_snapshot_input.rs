// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StartSnapshotInput {
    /// <p>The size of the volume, in GiB. The maximum size is <code>65536</code> GiB (64 TiB).</p>
    pub volume_size: ::std::option::Option<i64>,
    /// <p>The ID of the parent snapshot. If there is no parent snapshot, or if you are creating the first snapshot for an on-premises volume, omit this parameter.</p>
    /// <p>You can't specify <b>ParentSnapshotId</b> and <b>Encrypted</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>If you specify an encrypted parent snapshot, you must have permission to use the KMS key that was used to encrypt the parent snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub parent_snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags to apply to the snapshot.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>A description for the snapshot.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully. The subsequent retries with the same client token return the result from the original successful request and they have no additional effect.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-direct-api-idempotency.html"> Idempotency for StartSnapshot API</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether to encrypt the snapshot.</p>
    /// <p>You can't specify <b>Encrypted</b> and <b> ParentSnapshotId</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub encrypted: ::std::option::Option<bool>,
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key to be used to encrypt the snapshot.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>The amount of time (in minutes) after which the snapshot is automatically cancelled if:</p>
    /// <ul>
    /// <li>
    /// <p>No blocks are written to the snapshot.</p></li>
    /// <li>
    /// <p>The snapshot is not completed after writing the last block of data.</p></li>
    /// </ul>
    /// <p>If no value is specified, the timeout defaults to <code>60</code> minutes.</p>
    pub timeout: ::std::option::Option<i32>,
}
impl StartSnapshotInput {
    /// <p>The size of the volume, in GiB. The maximum size is <code>65536</code> GiB (64 TiB).</p>
    pub fn volume_size(&self) -> ::std::option::Option<i64> {
        self.volume_size
    }
    /// <p>The ID of the parent snapshot. If there is no parent snapshot, or if you are creating the first snapshot for an on-premises volume, omit this parameter.</p>
    /// <p>You can't specify <b>ParentSnapshotId</b> and <b>Encrypted</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>If you specify an encrypted parent snapshot, you must have permission to use the KMS key that was used to encrypt the parent snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn parent_snapshot_id(&self) -> ::std::option::Option<&str> {
        self.parent_snapshot_id.as_deref()
    }
    /// <p>The tags to apply to the snapshot.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>A description for the snapshot.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully. The subsequent retries with the same client token return the result from the original successful request and they have no additional effect.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-direct-api-idempotency.html"> Idempotency for StartSnapshot API</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Indicates whether to encrypt the snapshot.</p>
    /// <p>You can't specify <b>Encrypted</b> and <b> ParentSnapshotId</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key to be used to encrypt the snapshot.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>The amount of time (in minutes) after which the snapshot is automatically cancelled if:</p>
    /// <ul>
    /// <li>
    /// <p>No blocks are written to the snapshot.</p></li>
    /// <li>
    /// <p>The snapshot is not completed after writing the last block of data.</p></li>
    /// </ul>
    /// <p>If no value is specified, the timeout defaults to <code>60</code> minutes.</p>
    pub fn timeout(&self) -> ::std::option::Option<i32> {
        self.timeout
    }
}
impl ::std::fmt::Debug for StartSnapshotInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartSnapshotInput");
        formatter.field("volume_size", &self.volume_size);
        formatter.field("parent_snapshot_id", &self.parent_snapshot_id);
        formatter.field("tags", &self.tags);
        formatter.field("description", &self.description);
        formatter.field("client_token", &self.client_token);
        formatter.field("encrypted", &self.encrypted);
        formatter.field("kms_key_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("timeout", &self.timeout);
        formatter.finish()
    }
}
impl StartSnapshotInput {
    /// Creates a new builder-style object to manufacture [`StartSnapshotInput`](crate::operation::start_snapshot::StartSnapshotInput).
    pub fn builder() -> crate::operation::start_snapshot::builders::StartSnapshotInputBuilder {
        crate::operation::start_snapshot::builders::StartSnapshotInputBuilder::default()
    }
}

/// A builder for [`StartSnapshotInput`](crate::operation::start_snapshot::StartSnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StartSnapshotInputBuilder {
    pub(crate) volume_size: ::std::option::Option<i64>,
    pub(crate) parent_snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) encrypted: ::std::option::Option<bool>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) timeout: ::std::option::Option<i32>,
}
impl StartSnapshotInputBuilder {
    /// <p>The size of the volume, in GiB. The maximum size is <code>65536</code> GiB (64 TiB).</p>
    /// This field is required.
    pub fn volume_size(mut self, input: i64) -> Self {
        self.volume_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the volume, in GiB. The maximum size is <code>65536</code> GiB (64 TiB).</p>
    pub fn set_volume_size(mut self, input: ::std::option::Option<i64>) -> Self {
        self.volume_size = input;
        self
    }
    /// <p>The size of the volume, in GiB. The maximum size is <code>65536</code> GiB (64 TiB).</p>
    pub fn get_volume_size(&self) -> &::std::option::Option<i64> {
        &self.volume_size
    }
    /// <p>The ID of the parent snapshot. If there is no parent snapshot, or if you are creating the first snapshot for an on-premises volume, omit this parameter.</p>
    /// <p>You can't specify <b>ParentSnapshotId</b> and <b>Encrypted</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>If you specify an encrypted parent snapshot, you must have permission to use the KMS key that was used to encrypt the parent snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn parent_snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the parent snapshot. If there is no parent snapshot, or if you are creating the first snapshot for an on-premises volume, omit this parameter.</p>
    /// <p>You can't specify <b>ParentSnapshotId</b> and <b>Encrypted</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>If you specify an encrypted parent snapshot, you must have permission to use the KMS key that was used to encrypt the parent snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn set_parent_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_snapshot_id = input;
        self
    }
    /// <p>The ID of the parent snapshot. If there is no parent snapshot, or if you are creating the first snapshot for an on-premises volume, omit this parameter.</p>
    /// <p>You can't specify <b>ParentSnapshotId</b> and <b>Encrypted</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>If you specify an encrypted parent snapshot, you must have permission to use the KMS key that was used to encrypt the parent snapshot. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn get_parent_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_snapshot_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to apply to the snapshot.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to apply to the snapshot.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to apply to the snapshot.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>A description for the snapshot.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the snapshot.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the snapshot.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully. The subsequent retries with the same client token return the result from the original successful request and they have no additional effect.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-direct-api-idempotency.html"> Idempotency for StartSnapshot API</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully. The subsequent retries with the same client token return the result from the original successful request and they have no additional effect.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-direct-api-idempotency.html"> Idempotency for StartSnapshot API</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. Idempotency ensures that an API request completes only once. With an idempotent request, if the original request completes successfully. The subsequent retries with the same client token return the result from the original successful request and they have no additional effect.</p>
    /// <p>If you do not specify a client token, one is automatically generated by the Amazon Web Services SDK.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-direct-api-idempotency.html"> Idempotency for StartSnapshot API</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Indicates whether to encrypt the snapshot.</p>
    /// <p>You can't specify <b>Encrypted</b> and <b> ParentSnapshotId</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to encrypt the snapshot.</p>
    /// <p>You can't specify <b>Encrypted</b> and <b> ParentSnapshotId</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Indicates whether to encrypt the snapshot.</p>
    /// <p>You can't specify <b>Encrypted</b> and <b> ParentSnapshotId</b> in the same request. If you specify both parameters, the request fails with <code>ValidationException</code>.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key to be used to encrypt the snapshot.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key to be used to encrypt the snapshot.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Key Management Service (KMS) key to be used to encrypt the snapshot.</p>
    /// <p>The encryption status of the snapshot depends on the values that you specify for <b>Encrypted</b>, <b>KmsKeyArn</b>, and <b>ParentSnapshotId</b>, and whether your Amazon Web Services account is enabled for <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"> encryption by default</a>. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapis-using-encryption.html"> Using encryption</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p><important>
    /// <p>To create an encrypted snapshot, you must have permission to use the KMS key. For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebsapi-permissions.html#ebsapi-kms-permissions"> Permissions to use Key Management Service keys</a> in the <i>Amazon Elastic Compute Cloud User Guide</i>.</p>
    /// </important>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// <p>The amount of time (in minutes) after which the snapshot is automatically cancelled if:</p>
    /// <ul>
    /// <li>
    /// <p>No blocks are written to the snapshot.</p></li>
    /// <li>
    /// <p>The snapshot is not completed after writing the last block of data.</p></li>
    /// </ul>
    /// <p>If no value is specified, the timeout defaults to <code>60</code> minutes.</p>
    pub fn timeout(mut self, input: i32) -> Self {
        self.timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time (in minutes) after which the snapshot is automatically cancelled if:</p>
    /// <ul>
    /// <li>
    /// <p>No blocks are written to the snapshot.</p></li>
    /// <li>
    /// <p>The snapshot is not completed after writing the last block of data.</p></li>
    /// </ul>
    /// <p>If no value is specified, the timeout defaults to <code>60</code> minutes.</p>
    pub fn set_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.timeout = input;
        self
    }
    /// <p>The amount of time (in minutes) after which the snapshot is automatically cancelled if:</p>
    /// <ul>
    /// <li>
    /// <p>No blocks are written to the snapshot.</p></li>
    /// <li>
    /// <p>The snapshot is not completed after writing the last block of data.</p></li>
    /// </ul>
    /// <p>If no value is specified, the timeout defaults to <code>60</code> minutes.</p>
    pub fn get_timeout(&self) -> &::std::option::Option<i32> {
        &self.timeout
    }
    /// Consumes the builder and constructs a [`StartSnapshotInput`](crate::operation::start_snapshot::StartSnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_snapshot::StartSnapshotInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_snapshot::StartSnapshotInput {
            volume_size: self.volume_size,
            parent_snapshot_id: self.parent_snapshot_id,
            tags: self.tags,
            description: self.description,
            client_token: self.client_token,
            encrypted: self.encrypted,
            kms_key_arn: self.kms_key_arn,
            timeout: self.timeout,
        })
    }
}
impl ::std::fmt::Debug for StartSnapshotInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartSnapshotInputBuilder");
        formatter.field("volume_size", &self.volume_size);
        formatter.field("parent_snapshot_id", &self.parent_snapshot_id);
        formatter.field("tags", &self.tags);
        formatter.field("description", &self.description);
        formatter.field("client_token", &self.client_token);
        formatter.field("encrypted", &self.encrypted);
        formatter.field("kms_key_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("timeout", &self.timeout);
        formatter.finish()
    }
}
