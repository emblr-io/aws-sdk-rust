// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input values for <code>GetVaultLock</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetVaultLockInput {
    /// <p>The <code>AccountId</code> value is the AWS account ID of the account that owns the vault. You can either specify an AWS account ID or optionally a single '<code>-</code>' (hyphen), in which case Amazon S3 Glacier uses the AWS account ID associated with the credentials used to sign the request. If you use an account ID, do not include any hyphens ('-') in the ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the vault.</p>
    pub vault_name: ::std::option::Option<::std::string::String>,
}
impl GetVaultLockInput {
    /// <p>The <code>AccountId</code> value is the AWS account ID of the account that owns the vault. You can either specify an AWS account ID or optionally a single '<code>-</code>' (hyphen), in which case Amazon S3 Glacier uses the AWS account ID associated with the credentials used to sign the request. If you use an account ID, do not include any hyphens ('-') in the ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The name of the vault.</p>
    pub fn vault_name(&self) -> ::std::option::Option<&str> {
        self.vault_name.as_deref()
    }
}
impl crate::glacier_interceptors::GlacierAccountId for GetVaultLockInput {
    fn account_id_mut(&mut self) -> &mut Option<String> {
        &mut self.account_id
    }
}
impl GetVaultLockInput {
    /// Creates a new builder-style object to manufacture [`GetVaultLockInput`](crate::operation::get_vault_lock::GetVaultLockInput).
    pub fn builder() -> crate::operation::get_vault_lock::builders::GetVaultLockInputBuilder {
        crate::operation::get_vault_lock::builders::GetVaultLockInputBuilder::default()
    }
}

/// A builder for [`GetVaultLockInput`](crate::operation::get_vault_lock::GetVaultLockInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetVaultLockInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) vault_name: ::std::option::Option<::std::string::String>,
}
impl GetVaultLockInputBuilder {
    /// <p>The <code>AccountId</code> value is the AWS account ID of the account that owns the vault. You can either specify an AWS account ID or optionally a single '<code>-</code>' (hyphen), in which case Amazon S3 Glacier uses the AWS account ID associated with the credentials used to sign the request. If you use an account ID, do not include any hyphens ('-') in the ID.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>AccountId</code> value is the AWS account ID of the account that owns the vault. You can either specify an AWS account ID or optionally a single '<code>-</code>' (hyphen), in which case Amazon S3 Glacier uses the AWS account ID associated with the credentials used to sign the request. If you use an account ID, do not include any hyphens ('-') in the ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The <code>AccountId</code> value is the AWS account ID of the account that owns the vault. You can either specify an AWS account ID or optionally a single '<code>-</code>' (hyphen), in which case Amazon S3 Glacier uses the AWS account ID associated with the credentials used to sign the request. If you use an account ID, do not include any hyphens ('-') in the ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The name of the vault.</p>
    /// This field is required.
    pub fn vault_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vault_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the vault.</p>
    pub fn set_vault_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vault_name = input;
        self
    }
    /// <p>The name of the vault.</p>
    pub fn get_vault_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vault_name
    }
    /// Consumes the builder and constructs a [`GetVaultLockInput`](crate::operation::get_vault_lock::GetVaultLockInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_vault_lock::GetVaultLockInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_vault_lock::GetVaultLockInput {
            account_id: self.account_id,
            vault_name: self.vault_name,
        })
    }
}
