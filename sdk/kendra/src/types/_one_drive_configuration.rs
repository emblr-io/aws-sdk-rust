// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the configuration information to connect to OneDrive as your data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OneDriveConfiguration {
    /// <p>The Azure Active Directory domain of the organization.</p>
    pub tenant_domain: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of an Secrets Managersecret that contains the user name and password to connect to OneDrive. The user name should be the application ID for the OneDrive application, and the password is the application key for the OneDrive application.</p>
    pub secret_arn: ::std::string::String,
    /// <p>A list of user accounts whose documents should be indexed.</p>
    pub one_drive_users: ::std::option::Option<crate::types::OneDriveUsers>,
    /// <p>A list of regular expression patterns to include certain documents in your OneDrive. Documents that match the patterns are included in the index. Documents that don't match the patterns are excluded from the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub inclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of regular expression patterns to exclude certain documents in your OneDrive. Documents that match the patterns are excluded from the index. Documents that don't match the patterns are included in the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub exclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of <code>DataSourceToIndexFieldMapping</code> objects that map OneDrive data source attributes or field names to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to OneDrive fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The OneDrive data source field names must exist in your OneDrive custom metadata.</p>
    pub field_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>,
    /// <p><code>TRUE</code> to disable local groups information.</p>
    pub disable_local_groups: bool,
}
impl OneDriveConfiguration {
    /// <p>The Azure Active Directory domain of the organization.</p>
    pub fn tenant_domain(&self) -> &str {
        use std::ops::Deref;
        self.tenant_domain.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an Secrets Managersecret that contains the user name and password to connect to OneDrive. The user name should be the application ID for the OneDrive application, and the password is the application key for the OneDrive application.</p>
    pub fn secret_arn(&self) -> &str {
        use std::ops::Deref;
        self.secret_arn.deref()
    }
    /// <p>A list of user accounts whose documents should be indexed.</p>
    pub fn one_drive_users(&self) -> ::std::option::Option<&crate::types::OneDriveUsers> {
        self.one_drive_users.as_ref()
    }
    /// <p>A list of regular expression patterns to include certain documents in your OneDrive. Documents that match the patterns are included in the index. Documents that don't match the patterns are excluded from the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inclusion_patterns.is_none()`.
    pub fn inclusion_patterns(&self) -> &[::std::string::String] {
        self.inclusion_patterns.as_deref().unwrap_or_default()
    }
    /// <p>A list of regular expression patterns to exclude certain documents in your OneDrive. Documents that match the patterns are excluded from the index. Documents that don't match the patterns are included in the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.exclusion_patterns.is_none()`.
    pub fn exclusion_patterns(&self) -> &[::std::string::String] {
        self.exclusion_patterns.as_deref().unwrap_or_default()
    }
    /// <p>A list of <code>DataSourceToIndexFieldMapping</code> objects that map OneDrive data source attributes or field names to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to OneDrive fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The OneDrive data source field names must exist in your OneDrive custom metadata.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.field_mappings.is_none()`.
    pub fn field_mappings(&self) -> &[crate::types::DataSourceToIndexFieldMapping] {
        self.field_mappings.as_deref().unwrap_or_default()
    }
    /// <p><code>TRUE</code> to disable local groups information.</p>
    pub fn disable_local_groups(&self) -> bool {
        self.disable_local_groups
    }
}
impl OneDriveConfiguration {
    /// Creates a new builder-style object to manufacture [`OneDriveConfiguration`](crate::types::OneDriveConfiguration).
    pub fn builder() -> crate::types::builders::OneDriveConfigurationBuilder {
        crate::types::builders::OneDriveConfigurationBuilder::default()
    }
}

/// A builder for [`OneDriveConfiguration`](crate::types::OneDriveConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OneDriveConfigurationBuilder {
    pub(crate) tenant_domain: ::std::option::Option<::std::string::String>,
    pub(crate) secret_arn: ::std::option::Option<::std::string::String>,
    pub(crate) one_drive_users: ::std::option::Option<crate::types::OneDriveUsers>,
    pub(crate) inclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) exclusion_patterns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) field_mappings: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>,
    pub(crate) disable_local_groups: ::std::option::Option<bool>,
}
impl OneDriveConfigurationBuilder {
    /// <p>The Azure Active Directory domain of the organization.</p>
    /// This field is required.
    pub fn tenant_domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tenant_domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Azure Active Directory domain of the organization.</p>
    pub fn set_tenant_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tenant_domain = input;
        self
    }
    /// <p>The Azure Active Directory domain of the organization.</p>
    pub fn get_tenant_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.tenant_domain
    }
    /// <p>The Amazon Resource Name (ARN) of an Secrets Managersecret that contains the user name and password to connect to OneDrive. The user name should be the application ID for the OneDrive application, and the password is the application key for the OneDrive application.</p>
    /// This field is required.
    pub fn secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an Secrets Managersecret that contains the user name and password to connect to OneDrive. The user name should be the application ID for the OneDrive application, and the password is the application key for the OneDrive application.</p>
    pub fn set_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an Secrets Managersecret that contains the user name and password to connect to OneDrive. The user name should be the application ID for the OneDrive application, and the password is the application key for the OneDrive application.</p>
    pub fn get_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_arn
    }
    /// <p>A list of user accounts whose documents should be indexed.</p>
    /// This field is required.
    pub fn one_drive_users(mut self, input: crate::types::OneDriveUsers) -> Self {
        self.one_drive_users = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of user accounts whose documents should be indexed.</p>
    pub fn set_one_drive_users(mut self, input: ::std::option::Option<crate::types::OneDriveUsers>) -> Self {
        self.one_drive_users = input;
        self
    }
    /// <p>A list of user accounts whose documents should be indexed.</p>
    pub fn get_one_drive_users(&self) -> &::std::option::Option<crate::types::OneDriveUsers> {
        &self.one_drive_users
    }
    /// Appends an item to `inclusion_patterns`.
    ///
    /// To override the contents of this collection use [`set_inclusion_patterns`](Self::set_inclusion_patterns).
    ///
    /// <p>A list of regular expression patterns to include certain documents in your OneDrive. Documents that match the patterns are included in the index. Documents that don't match the patterns are excluded from the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub fn inclusion_patterns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.inclusion_patterns.unwrap_or_default();
        v.push(input.into());
        self.inclusion_patterns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of regular expression patterns to include certain documents in your OneDrive. Documents that match the patterns are included in the index. Documents that don't match the patterns are excluded from the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub fn set_inclusion_patterns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inclusion_patterns = input;
        self
    }
    /// <p>A list of regular expression patterns to include certain documents in your OneDrive. Documents that match the patterns are included in the index. Documents that don't match the patterns are excluded from the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub fn get_inclusion_patterns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.inclusion_patterns
    }
    /// Appends an item to `exclusion_patterns`.
    ///
    /// To override the contents of this collection use [`set_exclusion_patterns`](Self::set_exclusion_patterns).
    ///
    /// <p>A list of regular expression patterns to exclude certain documents in your OneDrive. Documents that match the patterns are excluded from the index. Documents that don't match the patterns are included in the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub fn exclusion_patterns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.exclusion_patterns.unwrap_or_default();
        v.push(input.into());
        self.exclusion_patterns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of regular expression patterns to exclude certain documents in your OneDrive. Documents that match the patterns are excluded from the index. Documents that don't match the patterns are included in the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub fn set_exclusion_patterns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.exclusion_patterns = input;
        self
    }
    /// <p>A list of regular expression patterns to exclude certain documents in your OneDrive. Documents that match the patterns are excluded from the index. Documents that don't match the patterns are included in the index. If a document matches both an inclusion and exclusion pattern, the exclusion pattern takes precedence and the document isn't included in the index.</p>
    /// <p>The pattern is applied to the file name.</p>
    pub fn get_exclusion_patterns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.exclusion_patterns
    }
    /// Appends an item to `field_mappings`.
    ///
    /// To override the contents of this collection use [`set_field_mappings`](Self::set_field_mappings).
    ///
    /// <p>A list of <code>DataSourceToIndexFieldMapping</code> objects that map OneDrive data source attributes or field names to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to OneDrive fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The OneDrive data source field names must exist in your OneDrive custom metadata.</p>
    pub fn field_mappings(mut self, input: crate::types::DataSourceToIndexFieldMapping) -> Self {
        let mut v = self.field_mappings.unwrap_or_default();
        v.push(input);
        self.field_mappings = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>DataSourceToIndexFieldMapping</code> objects that map OneDrive data source attributes or field names to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to OneDrive fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The OneDrive data source field names must exist in your OneDrive custom metadata.</p>
    pub fn set_field_mappings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>>) -> Self {
        self.field_mappings = input;
        self
    }
    /// <p>A list of <code>DataSourceToIndexFieldMapping</code> objects that map OneDrive data source attributes or field names to Amazon Kendra index field names. To create custom fields, use the <code>UpdateIndex</code> API before you map to OneDrive fields. For more information, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/field-mapping.html">Mapping data source fields</a>. The OneDrive data source field names must exist in your OneDrive custom metadata.</p>
    pub fn get_field_mappings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSourceToIndexFieldMapping>> {
        &self.field_mappings
    }
    /// <p><code>TRUE</code> to disable local groups information.</p>
    pub fn disable_local_groups(mut self, input: bool) -> Self {
        self.disable_local_groups = ::std::option::Option::Some(input);
        self
    }
    /// <p><code>TRUE</code> to disable local groups information.</p>
    pub fn set_disable_local_groups(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disable_local_groups = input;
        self
    }
    /// <p><code>TRUE</code> to disable local groups information.</p>
    pub fn get_disable_local_groups(&self) -> &::std::option::Option<bool> {
        &self.disable_local_groups
    }
    /// Consumes the builder and constructs a [`OneDriveConfiguration`](crate::types::OneDriveConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`tenant_domain`](crate::types::builders::OneDriveConfigurationBuilder::tenant_domain)
    /// - [`secret_arn`](crate::types::builders::OneDriveConfigurationBuilder::secret_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::OneDriveConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OneDriveConfiguration {
            tenant_domain: self.tenant_domain.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "tenant_domain",
                    "tenant_domain was not specified but it is required when building OneDriveConfiguration",
                )
            })?,
            secret_arn: self.secret_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "secret_arn",
                    "secret_arn was not specified but it is required when building OneDriveConfiguration",
                )
            })?,
            one_drive_users: self.one_drive_users,
            inclusion_patterns: self.inclusion_patterns,
            exclusion_patterns: self.exclusion_patterns,
            field_mappings: self.field_mappings,
            disable_local_groups: self.disable_local_groups.unwrap_or_default(),
        })
    }
}
