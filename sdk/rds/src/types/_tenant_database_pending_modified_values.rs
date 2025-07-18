// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A response element in the <code>ModifyTenantDatabase</code> operation that describes changes that will be applied. Specific changes are identified by subelements.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TenantDatabasePendingModifiedValues {
    /// <p>The master password for the tenant database.</p>
    pub master_user_password: ::std::option::Option<::std::string::String>,
    /// <p>The name of the tenant database.</p>
    pub tenant_db_name: ::std::option::Option<::std::string::String>,
}
impl TenantDatabasePendingModifiedValues {
    /// <p>The master password for the tenant database.</p>
    pub fn master_user_password(&self) -> ::std::option::Option<&str> {
        self.master_user_password.as_deref()
    }
    /// <p>The name of the tenant database.</p>
    pub fn tenant_db_name(&self) -> ::std::option::Option<&str> {
        self.tenant_db_name.as_deref()
    }
}
impl ::std::fmt::Debug for TenantDatabasePendingModifiedValues {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TenantDatabasePendingModifiedValues");
        formatter.field("master_user_password", &"*** Sensitive Data Redacted ***");
        formatter.field("tenant_db_name", &self.tenant_db_name);
        formatter.finish()
    }
}
impl TenantDatabasePendingModifiedValues {
    /// Creates a new builder-style object to manufacture [`TenantDatabasePendingModifiedValues`](crate::types::TenantDatabasePendingModifiedValues).
    pub fn builder() -> crate::types::builders::TenantDatabasePendingModifiedValuesBuilder {
        crate::types::builders::TenantDatabasePendingModifiedValuesBuilder::default()
    }
}

/// A builder for [`TenantDatabasePendingModifiedValues`](crate::types::TenantDatabasePendingModifiedValues).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TenantDatabasePendingModifiedValuesBuilder {
    pub(crate) master_user_password: ::std::option::Option<::std::string::String>,
    pub(crate) tenant_db_name: ::std::option::Option<::std::string::String>,
}
impl TenantDatabasePendingModifiedValuesBuilder {
    /// <p>The master password for the tenant database.</p>
    pub fn master_user_password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_user_password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The master password for the tenant database.</p>
    pub fn set_master_user_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_user_password = input;
        self
    }
    /// <p>The master password for the tenant database.</p>
    pub fn get_master_user_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_user_password
    }
    /// <p>The name of the tenant database.</p>
    pub fn tenant_db_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tenant_db_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the tenant database.</p>
    pub fn set_tenant_db_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tenant_db_name = input;
        self
    }
    /// <p>The name of the tenant database.</p>
    pub fn get_tenant_db_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.tenant_db_name
    }
    /// Consumes the builder and constructs a [`TenantDatabasePendingModifiedValues`](crate::types::TenantDatabasePendingModifiedValues).
    pub fn build(self) -> crate::types::TenantDatabasePendingModifiedValues {
        crate::types::TenantDatabasePendingModifiedValues {
            master_user_password: self.master_user_password,
            tenant_db_name: self.tenant_db_name,
        }
    }
}
impl ::std::fmt::Debug for TenantDatabasePendingModifiedValuesBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TenantDatabasePendingModifiedValuesBuilder");
        formatter.field("master_user_password", &"*** Sensitive Data Redacted ***");
        formatter.field("tenant_db_name", &self.tenant_db_name);
        formatter.finish()
    }
}
