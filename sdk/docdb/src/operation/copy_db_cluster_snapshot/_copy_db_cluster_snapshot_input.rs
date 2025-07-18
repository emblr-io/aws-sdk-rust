// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input to <code>CopyDBClusterSnapshot</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopyDbClusterSnapshotInput {
    /// <p>The identifier of the cluster snapshot to copy. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must specify a valid system snapshot in the <i>available</i> state.</p></li>
    /// <li>
    /// <p>If the source snapshot is in the same Amazon Web Services Region as the copy, specify a valid snapshot identifier.</p></li>
    /// <li>
    /// <p>If the source snapshot is in a different Amazon Web Services Region than the copy, specify a valid cluster snapshot ARN.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot1</code></p>
    pub source_db_cluster_snapshot_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the new cluster snapshot to create from the source cluster snapshot. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot2</code></p>
    pub target_db_cluster_snapshot_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The KMS key ID for an encrypted cluster snapshot. The KMS key ID is the Amazon Resource Name (ARN), KMS key identifier, or the KMS key alias for the KMS encryption key.</p>
    /// <p>If you copy an encrypted cluster snapshot from your Amazon Web Services account, you can specify a value for <code>KmsKeyId</code> to encrypt the copy with a new KMS encryption key. If you don't specify a value for <code>KmsKeyId</code>, then the copy of the cluster snapshot is encrypted with the same KMS key as the source cluster snapshot.</p>
    /// <p>If you copy an encrypted cluster snapshot that is shared from another Amazon Web Services account, then you must specify a value for <code>KmsKeyId</code>.</p>
    /// <p>To copy an encrypted cluster snapshot to another Amazon Web Services Region, set <code>KmsKeyId</code> to the KMS key ID that you want to use to encrypt the copy of the cluster snapshot in the destination Region. KMS encryption keys are specific to the Amazon Web Services Region that they are created in, and you can't use encryption keys from one Amazon Web Services Region in another Amazon Web Services Region.</p>
    /// <p>If you copy an unencrypted cluster snapshot and specify a value for the <code>KmsKeyId</code> parameter, an error is returned.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The URL that contains a Signature Version 4 signed request for the<code>CopyDBClusterSnapshot</code> API action in the Amazon Web Services Region that contains the source cluster snapshot to copy. You must use the <code>PreSignedUrl</code> parameter when copying a cluster snapshot from another Amazon Web Services Region.</p>
    /// <p>If you are using an Amazon Web Services SDK tool or the CLI, you can specify <code>SourceRegion</code> (or <code>--source-region</code> for the CLI) instead of specifying <code>PreSignedUrl</code> manually. Specifying <code>SourceRegion</code> autogenerates a pre-signed URL that is a valid request for the operation that can be executed in the source Amazon Web Services Region.</p>
    /// <p>The presigned URL must be a valid request for the <code>CopyDBClusterSnapshot</code> API action that can be executed in the source Amazon Web Services Region that contains the cluster snapshot to be copied. The presigned URL request must contain the following parameter values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SourceRegion</code> - The ID of the region that contains the snapshot to be copied.</p></li>
    /// <li>
    /// <p><code>SourceDBClusterSnapshotIdentifier</code> - The identifier for the the encrypted cluster snapshot to be copied. This identifier must be in the Amazon Resource Name (ARN) format for the source Amazon Web Services Region. For example, if you are copying an encrypted cluster snapshot from the us-east-1 Amazon Web Services Region, then your <code>SourceDBClusterSnapshotIdentifier</code> looks something like the following: <code>arn:aws:rds:us-east-1:12345678012:sample-cluster:sample-cluster-snapshot</code>.</p></li>
    /// <li>
    /// <p><code>TargetDBClusterSnapshotIdentifier</code> - The identifier for the new cluster snapshot to be created. This parameter isn't case sensitive.</p></li>
    /// </ul>
    pub pre_signed_url: ::std::option::Option<::std::string::String>,
    /// <p>Set to <code>true</code> to copy all tags from the source cluster snapshot to the target cluster snapshot, and otherwise <code>false</code>. The default is <code>false</code>.</p>
    pub copy_tags: ::std::option::Option<bool>,
    /// <p>The tags to be assigned to the cluster snapshot.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CopyDbClusterSnapshotInput {
    /// <p>The identifier of the cluster snapshot to copy. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must specify a valid system snapshot in the <i>available</i> state.</p></li>
    /// <li>
    /// <p>If the source snapshot is in the same Amazon Web Services Region as the copy, specify a valid snapshot identifier.</p></li>
    /// <li>
    /// <p>If the source snapshot is in a different Amazon Web Services Region than the copy, specify a valid cluster snapshot ARN.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot1</code></p>
    pub fn source_db_cluster_snapshot_identifier(&self) -> ::std::option::Option<&str> {
        self.source_db_cluster_snapshot_identifier.as_deref()
    }
    /// <p>The identifier of the new cluster snapshot to create from the source cluster snapshot. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot2</code></p>
    pub fn target_db_cluster_snapshot_identifier(&self) -> ::std::option::Option<&str> {
        self.target_db_cluster_snapshot_identifier.as_deref()
    }
    /// <p>The KMS key ID for an encrypted cluster snapshot. The KMS key ID is the Amazon Resource Name (ARN), KMS key identifier, or the KMS key alias for the KMS encryption key.</p>
    /// <p>If you copy an encrypted cluster snapshot from your Amazon Web Services account, you can specify a value for <code>KmsKeyId</code> to encrypt the copy with a new KMS encryption key. If you don't specify a value for <code>KmsKeyId</code>, then the copy of the cluster snapshot is encrypted with the same KMS key as the source cluster snapshot.</p>
    /// <p>If you copy an encrypted cluster snapshot that is shared from another Amazon Web Services account, then you must specify a value for <code>KmsKeyId</code>.</p>
    /// <p>To copy an encrypted cluster snapshot to another Amazon Web Services Region, set <code>KmsKeyId</code> to the KMS key ID that you want to use to encrypt the copy of the cluster snapshot in the destination Region. KMS encryption keys are specific to the Amazon Web Services Region that they are created in, and you can't use encryption keys from one Amazon Web Services Region in another Amazon Web Services Region.</p>
    /// <p>If you copy an unencrypted cluster snapshot and specify a value for the <code>KmsKeyId</code> parameter, an error is returned.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The URL that contains a Signature Version 4 signed request for the<code>CopyDBClusterSnapshot</code> API action in the Amazon Web Services Region that contains the source cluster snapshot to copy. You must use the <code>PreSignedUrl</code> parameter when copying a cluster snapshot from another Amazon Web Services Region.</p>
    /// <p>If you are using an Amazon Web Services SDK tool or the CLI, you can specify <code>SourceRegion</code> (or <code>--source-region</code> for the CLI) instead of specifying <code>PreSignedUrl</code> manually. Specifying <code>SourceRegion</code> autogenerates a pre-signed URL that is a valid request for the operation that can be executed in the source Amazon Web Services Region.</p>
    /// <p>The presigned URL must be a valid request for the <code>CopyDBClusterSnapshot</code> API action that can be executed in the source Amazon Web Services Region that contains the cluster snapshot to be copied. The presigned URL request must contain the following parameter values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SourceRegion</code> - The ID of the region that contains the snapshot to be copied.</p></li>
    /// <li>
    /// <p><code>SourceDBClusterSnapshotIdentifier</code> - The identifier for the the encrypted cluster snapshot to be copied. This identifier must be in the Amazon Resource Name (ARN) format for the source Amazon Web Services Region. For example, if you are copying an encrypted cluster snapshot from the us-east-1 Amazon Web Services Region, then your <code>SourceDBClusterSnapshotIdentifier</code> looks something like the following: <code>arn:aws:rds:us-east-1:12345678012:sample-cluster:sample-cluster-snapshot</code>.</p></li>
    /// <li>
    /// <p><code>TargetDBClusterSnapshotIdentifier</code> - The identifier for the new cluster snapshot to be created. This parameter isn't case sensitive.</p></li>
    /// </ul>
    pub fn pre_signed_url(&self) -> ::std::option::Option<&str> {
        self.pre_signed_url.as_deref()
    }
    /// <p>Set to <code>true</code> to copy all tags from the source cluster snapshot to the target cluster snapshot, and otherwise <code>false</code>. The default is <code>false</code>.</p>
    pub fn copy_tags(&self) -> ::std::option::Option<bool> {
        self.copy_tags
    }
    /// <p>The tags to be assigned to the cluster snapshot.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CopyDbClusterSnapshotInput {
    /// Creates a new builder-style object to manufacture [`CopyDbClusterSnapshotInput`](crate::operation::copy_db_cluster_snapshot::CopyDbClusterSnapshotInput).
    pub fn builder() -> crate::operation::copy_db_cluster_snapshot::builders::CopyDbClusterSnapshotInputBuilder {
        crate::operation::copy_db_cluster_snapshot::builders::CopyDbClusterSnapshotInputBuilder::default()
    }
}

/// A builder for [`CopyDbClusterSnapshotInput`](crate::operation::copy_db_cluster_snapshot::CopyDbClusterSnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopyDbClusterSnapshotInputBuilder {
    pub(crate) source_db_cluster_snapshot_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) target_db_cluster_snapshot_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) pre_signed_url: ::std::option::Option<::std::string::String>,
    pub(crate) copy_tags: ::std::option::Option<bool>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CopyDbClusterSnapshotInputBuilder {
    /// <p>The identifier of the cluster snapshot to copy. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must specify a valid system snapshot in the <i>available</i> state.</p></li>
    /// <li>
    /// <p>If the source snapshot is in the same Amazon Web Services Region as the copy, specify a valid snapshot identifier.</p></li>
    /// <li>
    /// <p>If the source snapshot is in a different Amazon Web Services Region than the copy, specify a valid cluster snapshot ARN.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot1</code></p>
    /// This field is required.
    pub fn source_db_cluster_snapshot_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_db_cluster_snapshot_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the cluster snapshot to copy. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must specify a valid system snapshot in the <i>available</i> state.</p></li>
    /// <li>
    /// <p>If the source snapshot is in the same Amazon Web Services Region as the copy, specify a valid snapshot identifier.</p></li>
    /// <li>
    /// <p>If the source snapshot is in a different Amazon Web Services Region than the copy, specify a valid cluster snapshot ARN.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot1</code></p>
    pub fn set_source_db_cluster_snapshot_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_db_cluster_snapshot_identifier = input;
        self
    }
    /// <p>The identifier of the cluster snapshot to copy. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must specify a valid system snapshot in the <i>available</i> state.</p></li>
    /// <li>
    /// <p>If the source snapshot is in the same Amazon Web Services Region as the copy, specify a valid snapshot identifier.</p></li>
    /// <li>
    /// <p>If the source snapshot is in a different Amazon Web Services Region than the copy, specify a valid cluster snapshot ARN.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot1</code></p>
    pub fn get_source_db_cluster_snapshot_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_db_cluster_snapshot_identifier
    }
    /// <p>The identifier of the new cluster snapshot to create from the source cluster snapshot. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot2</code></p>
    /// This field is required.
    pub fn target_db_cluster_snapshot_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_db_cluster_snapshot_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the new cluster snapshot to create from the source cluster snapshot. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot2</code></p>
    pub fn set_target_db_cluster_snapshot_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_db_cluster_snapshot_identifier = input;
        self
    }
    /// <p>The identifier of the new cluster snapshot to create from the source cluster snapshot. This parameter is not case sensitive.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain from 1 to 63 letters, numbers, or hyphens.</p></li>
    /// <li>
    /// <p>The first character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    /// <p>Example: <code>my-cluster-snapshot2</code></p>
    pub fn get_target_db_cluster_snapshot_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_db_cluster_snapshot_identifier
    }
    /// <p>The KMS key ID for an encrypted cluster snapshot. The KMS key ID is the Amazon Resource Name (ARN), KMS key identifier, or the KMS key alias for the KMS encryption key.</p>
    /// <p>If you copy an encrypted cluster snapshot from your Amazon Web Services account, you can specify a value for <code>KmsKeyId</code> to encrypt the copy with a new KMS encryption key. If you don't specify a value for <code>KmsKeyId</code>, then the copy of the cluster snapshot is encrypted with the same KMS key as the source cluster snapshot.</p>
    /// <p>If you copy an encrypted cluster snapshot that is shared from another Amazon Web Services account, then you must specify a value for <code>KmsKeyId</code>.</p>
    /// <p>To copy an encrypted cluster snapshot to another Amazon Web Services Region, set <code>KmsKeyId</code> to the KMS key ID that you want to use to encrypt the copy of the cluster snapshot in the destination Region. KMS encryption keys are specific to the Amazon Web Services Region that they are created in, and you can't use encryption keys from one Amazon Web Services Region in another Amazon Web Services Region.</p>
    /// <p>If you copy an unencrypted cluster snapshot and specify a value for the <code>KmsKeyId</code> parameter, an error is returned.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key ID for an encrypted cluster snapshot. The KMS key ID is the Amazon Resource Name (ARN), KMS key identifier, or the KMS key alias for the KMS encryption key.</p>
    /// <p>If you copy an encrypted cluster snapshot from your Amazon Web Services account, you can specify a value for <code>KmsKeyId</code> to encrypt the copy with a new KMS encryption key. If you don't specify a value for <code>KmsKeyId</code>, then the copy of the cluster snapshot is encrypted with the same KMS key as the source cluster snapshot.</p>
    /// <p>If you copy an encrypted cluster snapshot that is shared from another Amazon Web Services account, then you must specify a value for <code>KmsKeyId</code>.</p>
    /// <p>To copy an encrypted cluster snapshot to another Amazon Web Services Region, set <code>KmsKeyId</code> to the KMS key ID that you want to use to encrypt the copy of the cluster snapshot in the destination Region. KMS encryption keys are specific to the Amazon Web Services Region that they are created in, and you can't use encryption keys from one Amazon Web Services Region in another Amazon Web Services Region.</p>
    /// <p>If you copy an unencrypted cluster snapshot and specify a value for the <code>KmsKeyId</code> parameter, an error is returned.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The KMS key ID for an encrypted cluster snapshot. The KMS key ID is the Amazon Resource Name (ARN), KMS key identifier, or the KMS key alias for the KMS encryption key.</p>
    /// <p>If you copy an encrypted cluster snapshot from your Amazon Web Services account, you can specify a value for <code>KmsKeyId</code> to encrypt the copy with a new KMS encryption key. If you don't specify a value for <code>KmsKeyId</code>, then the copy of the cluster snapshot is encrypted with the same KMS key as the source cluster snapshot.</p>
    /// <p>If you copy an encrypted cluster snapshot that is shared from another Amazon Web Services account, then you must specify a value for <code>KmsKeyId</code>.</p>
    /// <p>To copy an encrypted cluster snapshot to another Amazon Web Services Region, set <code>KmsKeyId</code> to the KMS key ID that you want to use to encrypt the copy of the cluster snapshot in the destination Region. KMS encryption keys are specific to the Amazon Web Services Region that they are created in, and you can't use encryption keys from one Amazon Web Services Region in another Amazon Web Services Region.</p>
    /// <p>If you copy an unencrypted cluster snapshot and specify a value for the <code>KmsKeyId</code> parameter, an error is returned.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The URL that contains a Signature Version 4 signed request for the<code>CopyDBClusterSnapshot</code> API action in the Amazon Web Services Region that contains the source cluster snapshot to copy. You must use the <code>PreSignedUrl</code> parameter when copying a cluster snapshot from another Amazon Web Services Region.</p>
    /// <p>If you are using an Amazon Web Services SDK tool or the CLI, you can specify <code>SourceRegion</code> (or <code>--source-region</code> for the CLI) instead of specifying <code>PreSignedUrl</code> manually. Specifying <code>SourceRegion</code> autogenerates a pre-signed URL that is a valid request for the operation that can be executed in the source Amazon Web Services Region.</p>
    /// <p>The presigned URL must be a valid request for the <code>CopyDBClusterSnapshot</code> API action that can be executed in the source Amazon Web Services Region that contains the cluster snapshot to be copied. The presigned URL request must contain the following parameter values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SourceRegion</code> - The ID of the region that contains the snapshot to be copied.</p></li>
    /// <li>
    /// <p><code>SourceDBClusterSnapshotIdentifier</code> - The identifier for the the encrypted cluster snapshot to be copied. This identifier must be in the Amazon Resource Name (ARN) format for the source Amazon Web Services Region. For example, if you are copying an encrypted cluster snapshot from the us-east-1 Amazon Web Services Region, then your <code>SourceDBClusterSnapshotIdentifier</code> looks something like the following: <code>arn:aws:rds:us-east-1:12345678012:sample-cluster:sample-cluster-snapshot</code>.</p></li>
    /// <li>
    /// <p><code>TargetDBClusterSnapshotIdentifier</code> - The identifier for the new cluster snapshot to be created. This parameter isn't case sensitive.</p></li>
    /// </ul>
    pub fn pre_signed_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pre_signed_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL that contains a Signature Version 4 signed request for the<code>CopyDBClusterSnapshot</code> API action in the Amazon Web Services Region that contains the source cluster snapshot to copy. You must use the <code>PreSignedUrl</code> parameter when copying a cluster snapshot from another Amazon Web Services Region.</p>
    /// <p>If you are using an Amazon Web Services SDK tool or the CLI, you can specify <code>SourceRegion</code> (or <code>--source-region</code> for the CLI) instead of specifying <code>PreSignedUrl</code> manually. Specifying <code>SourceRegion</code> autogenerates a pre-signed URL that is a valid request for the operation that can be executed in the source Amazon Web Services Region.</p>
    /// <p>The presigned URL must be a valid request for the <code>CopyDBClusterSnapshot</code> API action that can be executed in the source Amazon Web Services Region that contains the cluster snapshot to be copied. The presigned URL request must contain the following parameter values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SourceRegion</code> - The ID of the region that contains the snapshot to be copied.</p></li>
    /// <li>
    /// <p><code>SourceDBClusterSnapshotIdentifier</code> - The identifier for the the encrypted cluster snapshot to be copied. This identifier must be in the Amazon Resource Name (ARN) format for the source Amazon Web Services Region. For example, if you are copying an encrypted cluster snapshot from the us-east-1 Amazon Web Services Region, then your <code>SourceDBClusterSnapshotIdentifier</code> looks something like the following: <code>arn:aws:rds:us-east-1:12345678012:sample-cluster:sample-cluster-snapshot</code>.</p></li>
    /// <li>
    /// <p><code>TargetDBClusterSnapshotIdentifier</code> - The identifier for the new cluster snapshot to be created. This parameter isn't case sensitive.</p></li>
    /// </ul>
    pub fn set_pre_signed_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pre_signed_url = input;
        self
    }
    /// <p>The URL that contains a Signature Version 4 signed request for the<code>CopyDBClusterSnapshot</code> API action in the Amazon Web Services Region that contains the source cluster snapshot to copy. You must use the <code>PreSignedUrl</code> parameter when copying a cluster snapshot from another Amazon Web Services Region.</p>
    /// <p>If you are using an Amazon Web Services SDK tool or the CLI, you can specify <code>SourceRegion</code> (or <code>--source-region</code> for the CLI) instead of specifying <code>PreSignedUrl</code> manually. Specifying <code>SourceRegion</code> autogenerates a pre-signed URL that is a valid request for the operation that can be executed in the source Amazon Web Services Region.</p>
    /// <p>The presigned URL must be a valid request for the <code>CopyDBClusterSnapshot</code> API action that can be executed in the source Amazon Web Services Region that contains the cluster snapshot to be copied. The presigned URL request must contain the following parameter values:</p>
    /// <ul>
    /// <li>
    /// <p><code>SourceRegion</code> - The ID of the region that contains the snapshot to be copied.</p></li>
    /// <li>
    /// <p><code>SourceDBClusterSnapshotIdentifier</code> - The identifier for the the encrypted cluster snapshot to be copied. This identifier must be in the Amazon Resource Name (ARN) format for the source Amazon Web Services Region. For example, if you are copying an encrypted cluster snapshot from the us-east-1 Amazon Web Services Region, then your <code>SourceDBClusterSnapshotIdentifier</code> looks something like the following: <code>arn:aws:rds:us-east-1:12345678012:sample-cluster:sample-cluster-snapshot</code>.</p></li>
    /// <li>
    /// <p><code>TargetDBClusterSnapshotIdentifier</code> - The identifier for the new cluster snapshot to be created. This parameter isn't case sensitive.</p></li>
    /// </ul>
    pub fn get_pre_signed_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.pre_signed_url
    }
    /// <p>Set to <code>true</code> to copy all tags from the source cluster snapshot to the target cluster snapshot, and otherwise <code>false</code>. The default is <code>false</code>.</p>
    pub fn copy_tags(mut self, input: bool) -> Self {
        self.copy_tags = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>true</code> to copy all tags from the source cluster snapshot to the target cluster snapshot, and otherwise <code>false</code>. The default is <code>false</code>.</p>
    pub fn set_copy_tags(mut self, input: ::std::option::Option<bool>) -> Self {
        self.copy_tags = input;
        self
    }
    /// <p>Set to <code>true</code> to copy all tags from the source cluster snapshot to the target cluster snapshot, and otherwise <code>false</code>. The default is <code>false</code>.</p>
    pub fn get_copy_tags(&self) -> &::std::option::Option<bool> {
        &self.copy_tags
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to be assigned to the cluster snapshot.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to be assigned to the cluster snapshot.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to be assigned to the cluster snapshot.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CopyDbClusterSnapshotInput`](crate::operation::copy_db_cluster_snapshot::CopyDbClusterSnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::copy_db_cluster_snapshot::CopyDbClusterSnapshotInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::copy_db_cluster_snapshot::CopyDbClusterSnapshotInput {
            source_db_cluster_snapshot_identifier: self.source_db_cluster_snapshot_identifier,
            target_db_cluster_snapshot_identifier: self.target_db_cluster_snapshot_identifier,
            kms_key_id: self.kms_key_id,
            pre_signed_url: self.pre_signed_url,
            copy_tags: self.copy_tags,
            tags: self.tags,
        })
    }
}
