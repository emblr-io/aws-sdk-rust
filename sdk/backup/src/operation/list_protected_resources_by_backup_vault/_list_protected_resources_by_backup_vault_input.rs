// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProtectedResourcesByBackupVaultInput {
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by name.</p>
    pub backup_vault_name: ::std::option::Option<::std::string::String>,
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by account ID.</p>
    pub backup_vault_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to be returned.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListProtectedResourcesByBackupVaultInput {
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by name.</p>
    pub fn backup_vault_name(&self) -> ::std::option::Option<&str> {
        self.backup_vault_name.as_deref()
    }
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by account ID.</p>
    pub fn backup_vault_account_id(&self) -> ::std::option::Option<&str> {
        self.backup_vault_account_id.as_deref()
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListProtectedResourcesByBackupVaultInput {
    /// Creates a new builder-style object to manufacture [`ListProtectedResourcesByBackupVaultInput`](crate::operation::list_protected_resources_by_backup_vault::ListProtectedResourcesByBackupVaultInput).
    pub fn builder() -> crate::operation::list_protected_resources_by_backup_vault::builders::ListProtectedResourcesByBackupVaultInputBuilder {
        crate::operation::list_protected_resources_by_backup_vault::builders::ListProtectedResourcesByBackupVaultInputBuilder::default()
    }
}

/// A builder for [`ListProtectedResourcesByBackupVaultInput`](crate::operation::list_protected_resources_by_backup_vault::ListProtectedResourcesByBackupVaultInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProtectedResourcesByBackupVaultInputBuilder {
    pub(crate) backup_vault_name: ::std::option::Option<::std::string::String>,
    pub(crate) backup_vault_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListProtectedResourcesByBackupVaultInputBuilder {
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by name.</p>
    /// This field is required.
    pub fn backup_vault_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_vault_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by name.</p>
    pub fn set_backup_vault_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_vault_name = input;
        self
    }
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by name.</p>
    pub fn get_backup_vault_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_vault_name
    }
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by account ID.</p>
    pub fn backup_vault_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_vault_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by account ID.</p>
    pub fn set_backup_vault_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_vault_account_id = input;
        self
    }
    /// <p>The list of protected resources by backup vault within the vault(s) you specify by account ID.</p>
    pub fn get_backup_vault_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_vault_account_id
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next item following a partial list of returned items. For example, if a request is made to return <code>MaxResults</code> number of items, <code>NextToken</code> allows you to return more items in your list starting at the location pointed to by the next token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to be returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListProtectedResourcesByBackupVaultInput`](crate::operation::list_protected_resources_by_backup_vault::ListProtectedResourcesByBackupVaultInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_protected_resources_by_backup_vault::ListProtectedResourcesByBackupVaultInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_protected_resources_by_backup_vault::ListProtectedResourcesByBackupVaultInput {
                backup_vault_name: self.backup_vault_name,
                backup_vault_account_id: self.backup_vault_account_id,
                next_token: self.next_token,
                max_results: self.max_results,
            },
        )
    }
}
