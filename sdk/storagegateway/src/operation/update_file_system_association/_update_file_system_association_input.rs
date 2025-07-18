// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateFileSystemAssociationInput {
    /// <p>The Amazon Resource Name (ARN) of the file system association that you want to update.</p>
    pub file_system_association_arn: ::std::option::Option<::std::string::String>,
    /// <p>The user name of the user credential that has permission to access the root share D$ of the Amazon FSx file system. The user account must belong to the Amazon FSx delegated admin user group.</p>
    pub user_name: ::std::option::Option<::std::string::String>,
    /// <p>The password of the user credential.</p>
    pub password: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the storage used for the audit logs.</p>
    pub audit_destination_arn: ::std::option::Option<::std::string::String>,
    /// <p>The refresh cache information for the file share or FSx file systems.</p>
    pub cache_attributes: ::std::option::Option<crate::types::CacheAttributes>,
}
impl UpdateFileSystemAssociationInput {
    /// <p>The Amazon Resource Name (ARN) of the file system association that you want to update.</p>
    pub fn file_system_association_arn(&self) -> ::std::option::Option<&str> {
        self.file_system_association_arn.as_deref()
    }
    /// <p>The user name of the user credential that has permission to access the root share D$ of the Amazon FSx file system. The user account must belong to the Amazon FSx delegated admin user group.</p>
    pub fn user_name(&self) -> ::std::option::Option<&str> {
        self.user_name.as_deref()
    }
    /// <p>The password of the user credential.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the storage used for the audit logs.</p>
    pub fn audit_destination_arn(&self) -> ::std::option::Option<&str> {
        self.audit_destination_arn.as_deref()
    }
    /// <p>The refresh cache information for the file share or FSx file systems.</p>
    pub fn cache_attributes(&self) -> ::std::option::Option<&crate::types::CacheAttributes> {
        self.cache_attributes.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateFileSystemAssociationInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateFileSystemAssociationInput");
        formatter.field("file_system_association_arn", &self.file_system_association_arn);
        formatter.field("user_name", &self.user_name);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("audit_destination_arn", &self.audit_destination_arn);
        formatter.field("cache_attributes", &self.cache_attributes);
        formatter.finish()
    }
}
impl UpdateFileSystemAssociationInput {
    /// Creates a new builder-style object to manufacture [`UpdateFileSystemAssociationInput`](crate::operation::update_file_system_association::UpdateFileSystemAssociationInput).
    pub fn builder() -> crate::operation::update_file_system_association::builders::UpdateFileSystemAssociationInputBuilder {
        crate::operation::update_file_system_association::builders::UpdateFileSystemAssociationInputBuilder::default()
    }
}

/// A builder for [`UpdateFileSystemAssociationInput`](crate::operation::update_file_system_association::UpdateFileSystemAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateFileSystemAssociationInputBuilder {
    pub(crate) file_system_association_arn: ::std::option::Option<::std::string::String>,
    pub(crate) user_name: ::std::option::Option<::std::string::String>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
    pub(crate) audit_destination_arn: ::std::option::Option<::std::string::String>,
    pub(crate) cache_attributes: ::std::option::Option<crate::types::CacheAttributes>,
}
impl UpdateFileSystemAssociationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the file system association that you want to update.</p>
    /// This field is required.
    pub fn file_system_association_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_association_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the file system association that you want to update.</p>
    pub fn set_file_system_association_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_association_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the file system association that you want to update.</p>
    pub fn get_file_system_association_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_association_arn
    }
    /// <p>The user name of the user credential that has permission to access the root share D$ of the Amazon FSx file system. The user account must belong to the Amazon FSx delegated admin user group.</p>
    pub fn user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user name of the user credential that has permission to access the root share D$ of the Amazon FSx file system. The user account must belong to the Amazon FSx delegated admin user group.</p>
    pub fn set_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_name = input;
        self
    }
    /// <p>The user name of the user credential that has permission to access the root share D$ of the Amazon FSx file system. The user account must belong to the Amazon FSx delegated admin user group.</p>
    pub fn get_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_name
    }
    /// <p>The password of the user credential.</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password of the user credential.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>The password of the user credential.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// <p>The Amazon Resource Name (ARN) of the storage used for the audit logs.</p>
    pub fn audit_destination_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.audit_destination_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the storage used for the audit logs.</p>
    pub fn set_audit_destination_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.audit_destination_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the storage used for the audit logs.</p>
    pub fn get_audit_destination_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.audit_destination_arn
    }
    /// <p>The refresh cache information for the file share or FSx file systems.</p>
    pub fn cache_attributes(mut self, input: crate::types::CacheAttributes) -> Self {
        self.cache_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The refresh cache information for the file share or FSx file systems.</p>
    pub fn set_cache_attributes(mut self, input: ::std::option::Option<crate::types::CacheAttributes>) -> Self {
        self.cache_attributes = input;
        self
    }
    /// <p>The refresh cache information for the file share or FSx file systems.</p>
    pub fn get_cache_attributes(&self) -> &::std::option::Option<crate::types::CacheAttributes> {
        &self.cache_attributes
    }
    /// Consumes the builder and constructs a [`UpdateFileSystemAssociationInput`](crate::operation::update_file_system_association::UpdateFileSystemAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_file_system_association::UpdateFileSystemAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_file_system_association::UpdateFileSystemAssociationInput {
            file_system_association_arn: self.file_system_association_arn,
            user_name: self.user_name,
            password: self.password,
            audit_destination_arn: self.audit_destination_arn,
            cache_attributes: self.cache_attributes,
        })
    }
}
impl ::std::fmt::Debug for UpdateFileSystemAssociationInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateFileSystemAssociationInputBuilder");
        formatter.field("file_system_association_arn", &self.file_system_association_arn);
        formatter.field("user_name", &self.user_name);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("audit_destination_arn", &self.audit_destination_arn);
        formatter.field("cache_attributes", &self.cache_attributes);
        formatter.finish()
    }
}
