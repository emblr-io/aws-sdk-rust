// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a custom tape pool.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PoolInfo {
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of custom tape pools for your account and Amazon Web Services Region.</p>
    pub pool_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the custom tape pool. <code>PoolName</code> can use all ASCII characters, except '/' and '\'.</p>
    pub pool_name: ::std::option::Option<::std::string::String>,
    /// <p>The storage class that is associated with the custom pool. When you use your backup application to eject the tape, the tape is archived directly into the storage class (S3 Glacier or S3 Glacier Deep Archive) that corresponds to the pool.</p>
    pub storage_class: ::std::option::Option<crate::types::TapeStorageClass>,
    /// <p>Tape retention lock type, which can be configured in two modes. When configured in governance mode, Amazon Web Services accounts with specific IAM permissions are authorized to remove the tape retention lock from archived virtual tapes. When configured in compliance mode, the tape retention lock cannot be removed by any user, including the root Amazon Web Services account.</p>
    pub retention_lock_type: ::std::option::Option<crate::types::RetentionLockType>,
    /// <p>Tape retention lock time is set in days. Tape retention lock can be enabled for up to 100 years (36,500 days).</p>
    pub retention_lock_time_in_days: ::std::option::Option<i32>,
    /// <p>Status of the custom tape pool. Pool can be <code>ACTIVE</code> or <code>DELETED</code>.</p>
    pub pool_status: ::std::option::Option<crate::types::PoolStatus>,
}
impl PoolInfo {
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of custom tape pools for your account and Amazon Web Services Region.</p>
    pub fn pool_arn(&self) -> ::std::option::Option<&str> {
        self.pool_arn.as_deref()
    }
    /// <p>The name of the custom tape pool. <code>PoolName</code> can use all ASCII characters, except '/' and '\'.</p>
    pub fn pool_name(&self) -> ::std::option::Option<&str> {
        self.pool_name.as_deref()
    }
    /// <p>The storage class that is associated with the custom pool. When you use your backup application to eject the tape, the tape is archived directly into the storage class (S3 Glacier or S3 Glacier Deep Archive) that corresponds to the pool.</p>
    pub fn storage_class(&self) -> ::std::option::Option<&crate::types::TapeStorageClass> {
        self.storage_class.as_ref()
    }
    /// <p>Tape retention lock type, which can be configured in two modes. When configured in governance mode, Amazon Web Services accounts with specific IAM permissions are authorized to remove the tape retention lock from archived virtual tapes. When configured in compliance mode, the tape retention lock cannot be removed by any user, including the root Amazon Web Services account.</p>
    pub fn retention_lock_type(&self) -> ::std::option::Option<&crate::types::RetentionLockType> {
        self.retention_lock_type.as_ref()
    }
    /// <p>Tape retention lock time is set in days. Tape retention lock can be enabled for up to 100 years (36,500 days).</p>
    pub fn retention_lock_time_in_days(&self) -> ::std::option::Option<i32> {
        self.retention_lock_time_in_days
    }
    /// <p>Status of the custom tape pool. Pool can be <code>ACTIVE</code> or <code>DELETED</code>.</p>
    pub fn pool_status(&self) -> ::std::option::Option<&crate::types::PoolStatus> {
        self.pool_status.as_ref()
    }
}
impl PoolInfo {
    /// Creates a new builder-style object to manufacture [`PoolInfo`](crate::types::PoolInfo).
    pub fn builder() -> crate::types::builders::PoolInfoBuilder {
        crate::types::builders::PoolInfoBuilder::default()
    }
}

/// A builder for [`PoolInfo`](crate::types::PoolInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PoolInfoBuilder {
    pub(crate) pool_arn: ::std::option::Option<::std::string::String>,
    pub(crate) pool_name: ::std::option::Option<::std::string::String>,
    pub(crate) storage_class: ::std::option::Option<crate::types::TapeStorageClass>,
    pub(crate) retention_lock_type: ::std::option::Option<crate::types::RetentionLockType>,
    pub(crate) retention_lock_time_in_days: ::std::option::Option<i32>,
    pub(crate) pool_status: ::std::option::Option<crate::types::PoolStatus>,
}
impl PoolInfoBuilder {
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of custom tape pools for your account and Amazon Web Services Region.</p>
    pub fn pool_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pool_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of custom tape pools for your account and Amazon Web Services Region.</p>
    pub fn set_pool_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pool_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom tape pool. Use the <code>ListTapePools</code> operation to return a list of custom tape pools for your account and Amazon Web Services Region.</p>
    pub fn get_pool_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.pool_arn
    }
    /// <p>The name of the custom tape pool. <code>PoolName</code> can use all ASCII characters, except '/' and '\'.</p>
    pub fn pool_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pool_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom tape pool. <code>PoolName</code> can use all ASCII characters, except '/' and '\'.</p>
    pub fn set_pool_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pool_name = input;
        self
    }
    /// <p>The name of the custom tape pool. <code>PoolName</code> can use all ASCII characters, except '/' and '\'.</p>
    pub fn get_pool_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.pool_name
    }
    /// <p>The storage class that is associated with the custom pool. When you use your backup application to eject the tape, the tape is archived directly into the storage class (S3 Glacier or S3 Glacier Deep Archive) that corresponds to the pool.</p>
    pub fn storage_class(mut self, input: crate::types::TapeStorageClass) -> Self {
        self.storage_class = ::std::option::Option::Some(input);
        self
    }
    /// <p>The storage class that is associated with the custom pool. When you use your backup application to eject the tape, the tape is archived directly into the storage class (S3 Glacier or S3 Glacier Deep Archive) that corresponds to the pool.</p>
    pub fn set_storage_class(mut self, input: ::std::option::Option<crate::types::TapeStorageClass>) -> Self {
        self.storage_class = input;
        self
    }
    /// <p>The storage class that is associated with the custom pool. When you use your backup application to eject the tape, the tape is archived directly into the storage class (S3 Glacier or S3 Glacier Deep Archive) that corresponds to the pool.</p>
    pub fn get_storage_class(&self) -> &::std::option::Option<crate::types::TapeStorageClass> {
        &self.storage_class
    }
    /// <p>Tape retention lock type, which can be configured in two modes. When configured in governance mode, Amazon Web Services accounts with specific IAM permissions are authorized to remove the tape retention lock from archived virtual tapes. When configured in compliance mode, the tape retention lock cannot be removed by any user, including the root Amazon Web Services account.</p>
    pub fn retention_lock_type(mut self, input: crate::types::RetentionLockType) -> Self {
        self.retention_lock_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Tape retention lock type, which can be configured in two modes. When configured in governance mode, Amazon Web Services accounts with specific IAM permissions are authorized to remove the tape retention lock from archived virtual tapes. When configured in compliance mode, the tape retention lock cannot be removed by any user, including the root Amazon Web Services account.</p>
    pub fn set_retention_lock_type(mut self, input: ::std::option::Option<crate::types::RetentionLockType>) -> Self {
        self.retention_lock_type = input;
        self
    }
    /// <p>Tape retention lock type, which can be configured in two modes. When configured in governance mode, Amazon Web Services accounts with specific IAM permissions are authorized to remove the tape retention lock from archived virtual tapes. When configured in compliance mode, the tape retention lock cannot be removed by any user, including the root Amazon Web Services account.</p>
    pub fn get_retention_lock_type(&self) -> &::std::option::Option<crate::types::RetentionLockType> {
        &self.retention_lock_type
    }
    /// <p>Tape retention lock time is set in days. Tape retention lock can be enabled for up to 100 years (36,500 days).</p>
    pub fn retention_lock_time_in_days(mut self, input: i32) -> Self {
        self.retention_lock_time_in_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>Tape retention lock time is set in days. Tape retention lock can be enabled for up to 100 years (36,500 days).</p>
    pub fn set_retention_lock_time_in_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retention_lock_time_in_days = input;
        self
    }
    /// <p>Tape retention lock time is set in days. Tape retention lock can be enabled for up to 100 years (36,500 days).</p>
    pub fn get_retention_lock_time_in_days(&self) -> &::std::option::Option<i32> {
        &self.retention_lock_time_in_days
    }
    /// <p>Status of the custom tape pool. Pool can be <code>ACTIVE</code> or <code>DELETED</code>.</p>
    pub fn pool_status(mut self, input: crate::types::PoolStatus) -> Self {
        self.pool_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the custom tape pool. Pool can be <code>ACTIVE</code> or <code>DELETED</code>.</p>
    pub fn set_pool_status(mut self, input: ::std::option::Option<crate::types::PoolStatus>) -> Self {
        self.pool_status = input;
        self
    }
    /// <p>Status of the custom tape pool. Pool can be <code>ACTIVE</code> or <code>DELETED</code>.</p>
    pub fn get_pool_status(&self) -> &::std::option::Option<crate::types::PoolStatus> {
        &self.pool_status
    }
    /// Consumes the builder and constructs a [`PoolInfo`](crate::types::PoolInfo).
    pub fn build(self) -> crate::types::PoolInfo {
        crate::types::PoolInfo {
            pool_arn: self.pool_arn,
            pool_name: self.pool_name,
            storage_class: self.storage_class,
            retention_lock_type: self.retention_lock_type,
            retention_lock_time_in_days: self.retention_lock_time_in_days,
            pool_status: self.pool_status,
        }
    }
}
