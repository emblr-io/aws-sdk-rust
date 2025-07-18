// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBackupVaultNotificationsInput {
    /// <p>The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Region where they are created.</p>
    pub backup_vault_name: ::std::option::Option<::std::string::String>,
}
impl DeleteBackupVaultNotificationsInput {
    /// <p>The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Region where they are created.</p>
    pub fn backup_vault_name(&self) -> ::std::option::Option<&str> {
        self.backup_vault_name.as_deref()
    }
}
impl DeleteBackupVaultNotificationsInput {
    /// Creates a new builder-style object to manufacture [`DeleteBackupVaultNotificationsInput`](crate::operation::delete_backup_vault_notifications::DeleteBackupVaultNotificationsInput).
    pub fn builder() -> crate::operation::delete_backup_vault_notifications::builders::DeleteBackupVaultNotificationsInputBuilder {
        crate::operation::delete_backup_vault_notifications::builders::DeleteBackupVaultNotificationsInputBuilder::default()
    }
}

/// A builder for [`DeleteBackupVaultNotificationsInput`](crate::operation::delete_backup_vault_notifications::DeleteBackupVaultNotificationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteBackupVaultNotificationsInputBuilder {
    pub(crate) backup_vault_name: ::std::option::Option<::std::string::String>,
}
impl DeleteBackupVaultNotificationsInputBuilder {
    /// <p>The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Region where they are created.</p>
    /// This field is required.
    pub fn backup_vault_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backup_vault_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Region where they are created.</p>
    pub fn set_backup_vault_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backup_vault_name = input;
        self
    }
    /// <p>The name of a logical container where backups are stored. Backup vaults are identified by names that are unique to the account used to create them and the Region where they are created.</p>
    pub fn get_backup_vault_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backup_vault_name
    }
    /// Consumes the builder and constructs a [`DeleteBackupVaultNotificationsInput`](crate::operation::delete_backup_vault_notifications::DeleteBackupVaultNotificationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_backup_vault_notifications::DeleteBackupVaultNotificationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_backup_vault_notifications::DeleteBackupVaultNotificationsInput {
            backup_vault_name: self.backup_vault_name,
        })
    }
}
