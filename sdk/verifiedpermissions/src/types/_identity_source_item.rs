// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that defines an identity source.</p>
/// <p>This data type is a response parameter to the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListIdentitySources.html">ListIdentitySources</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct IdentitySourceItem {
    /// <p>The date and time the identity source was originally created.</p>
    pub created_date: ::aws_smithy_types::DateTime,
    /// <p>A structure that contains the details of the associated identity provider (IdP).</p>
    #[deprecated(note = "This attribute has been replaced by configuration.cognitoUserPoolConfiguration")]
    pub details: ::std::option::Option<crate::types::IdentitySourceItemDetails>,
    /// <p>The unique identifier of the identity source.</p>
    pub identity_source_id: ::std::string::String,
    /// <p>The date and time the identity source was most recently updated.</p>
    pub last_updated_date: ::aws_smithy_types::DateTime,
    /// <p>The identifier of the policy store that contains the identity source.</p>
    pub policy_store_id: ::std::string::String,
    /// <p>The Cedar entity type of the principals returned from the IdP associated with this identity source.</p>
    pub principal_entity_type: ::std::string::String,
    /// <p>Contains configuration information about an identity source.</p>
    pub configuration: ::std::option::Option<crate::types::ConfigurationItem>,
}
impl IdentitySourceItem {
    /// <p>The date and time the identity source was originally created.</p>
    pub fn created_date(&self) -> &::aws_smithy_types::DateTime {
        &self.created_date
    }
    /// <p>A structure that contains the details of the associated identity provider (IdP).</p>
    #[deprecated(note = "This attribute has been replaced by configuration.cognitoUserPoolConfiguration")]
    pub fn details(&self) -> ::std::option::Option<&crate::types::IdentitySourceItemDetails> {
        self.details.as_ref()
    }
    /// <p>The unique identifier of the identity source.</p>
    pub fn identity_source_id(&self) -> &str {
        use std::ops::Deref;
        self.identity_source_id.deref()
    }
    /// <p>The date and time the identity source was most recently updated.</p>
    pub fn last_updated_date(&self) -> &::aws_smithy_types::DateTime {
        &self.last_updated_date
    }
    /// <p>The identifier of the policy store that contains the identity source.</p>
    pub fn policy_store_id(&self) -> &str {
        use std::ops::Deref;
        self.policy_store_id.deref()
    }
    /// <p>The Cedar entity type of the principals returned from the IdP associated with this identity source.</p>
    pub fn principal_entity_type(&self) -> &str {
        use std::ops::Deref;
        self.principal_entity_type.deref()
    }
    /// <p>Contains configuration information about an identity source.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::ConfigurationItem> {
        self.configuration.as_ref()
    }
}
impl ::std::fmt::Debug for IdentitySourceItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IdentitySourceItem");
        formatter.field("created_date", &self.created_date);
        formatter.field("details", &self.details);
        formatter.field("identity_source_id", &self.identity_source_id);
        formatter.field("last_updated_date", &self.last_updated_date);
        formatter.field("policy_store_id", &self.policy_store_id);
        formatter.field("principal_entity_type", &"*** Sensitive Data Redacted ***");
        formatter.field("configuration", &self.configuration);
        formatter.finish()
    }
}
impl IdentitySourceItem {
    /// Creates a new builder-style object to manufacture [`IdentitySourceItem`](crate::types::IdentitySourceItem).
    pub fn builder() -> crate::types::builders::IdentitySourceItemBuilder {
        crate::types::builders::IdentitySourceItemBuilder::default()
    }
}

/// A builder for [`IdentitySourceItem`](crate::types::IdentitySourceItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct IdentitySourceItemBuilder {
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) details: ::std::option::Option<crate::types::IdentitySourceItemDetails>,
    pub(crate) identity_source_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) policy_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) principal_entity_type: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::ConfigurationItem>,
}
impl IdentitySourceItemBuilder {
    /// <p>The date and time the identity source was originally created.</p>
    /// This field is required.
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the identity source was originally created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The date and time the identity source was originally created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// <p>A structure that contains the details of the associated identity provider (IdP).</p>
    #[deprecated(note = "This attribute has been replaced by configuration.cognitoUserPoolConfiguration")]
    pub fn details(mut self, input: crate::types::IdentitySourceItemDetails) -> Self {
        self.details = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains the details of the associated identity provider (IdP).</p>
    #[deprecated(note = "This attribute has been replaced by configuration.cognitoUserPoolConfiguration")]
    pub fn set_details(mut self, input: ::std::option::Option<crate::types::IdentitySourceItemDetails>) -> Self {
        self.details = input;
        self
    }
    /// <p>A structure that contains the details of the associated identity provider (IdP).</p>
    #[deprecated(note = "This attribute has been replaced by configuration.cognitoUserPoolConfiguration")]
    pub fn get_details(&self) -> &::std::option::Option<crate::types::IdentitySourceItemDetails> {
        &self.details
    }
    /// <p>The unique identifier of the identity source.</p>
    /// This field is required.
    pub fn identity_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the identity source.</p>
    pub fn set_identity_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_source_id = input;
        self
    }
    /// <p>The unique identifier of the identity source.</p>
    pub fn get_identity_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_source_id
    }
    /// <p>The date and time the identity source was most recently updated.</p>
    /// This field is required.
    pub fn last_updated_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the identity source was most recently updated.</p>
    pub fn set_last_updated_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date = input;
        self
    }
    /// <p>The date and time the identity source was most recently updated.</p>
    pub fn get_last_updated_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date
    }
    /// <p>The identifier of the policy store that contains the identity source.</p>
    /// This field is required.
    pub fn policy_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the policy store that contains the identity source.</p>
    pub fn set_policy_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_store_id = input;
        self
    }
    /// <p>The identifier of the policy store that contains the identity source.</p>
    pub fn get_policy_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_store_id
    }
    /// <p>The Cedar entity type of the principals returned from the IdP associated with this identity source.</p>
    /// This field is required.
    pub fn principal_entity_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_entity_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Cedar entity type of the principals returned from the IdP associated with this identity source.</p>
    pub fn set_principal_entity_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_entity_type = input;
        self
    }
    /// <p>The Cedar entity type of the principals returned from the IdP associated with this identity source.</p>
    pub fn get_principal_entity_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_entity_type
    }
    /// <p>Contains configuration information about an identity source.</p>
    pub fn configuration(mut self, input: crate::types::ConfigurationItem) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains configuration information about an identity source.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::ConfigurationItem>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>Contains configuration information about an identity source.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::ConfigurationItem> {
        &self.configuration
    }
    /// Consumes the builder and constructs a [`IdentitySourceItem`](crate::types::IdentitySourceItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`created_date`](crate::types::builders::IdentitySourceItemBuilder::created_date)
    /// - [`identity_source_id`](crate::types::builders::IdentitySourceItemBuilder::identity_source_id)
    /// - [`last_updated_date`](crate::types::builders::IdentitySourceItemBuilder::last_updated_date)
    /// - [`policy_store_id`](crate::types::builders::IdentitySourceItemBuilder::policy_store_id)
    /// - [`principal_entity_type`](crate::types::builders::IdentitySourceItemBuilder::principal_entity_type)
    pub fn build(self) -> ::std::result::Result<crate::types::IdentitySourceItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IdentitySourceItem {
            created_date: self.created_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_date",
                    "created_date was not specified but it is required when building IdentitySourceItem",
                )
            })?,
            details: self.details,
            identity_source_id: self.identity_source_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identity_source_id",
                    "identity_source_id was not specified but it is required when building IdentitySourceItem",
                )
            })?,
            last_updated_date: self.last_updated_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_updated_date",
                    "last_updated_date was not specified but it is required when building IdentitySourceItem",
                )
            })?,
            policy_store_id: self.policy_store_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "policy_store_id",
                    "policy_store_id was not specified but it is required when building IdentitySourceItem",
                )
            })?,
            principal_entity_type: self.principal_entity_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "principal_entity_type",
                    "principal_entity_type was not specified but it is required when building IdentitySourceItem",
                )
            })?,
            configuration: self.configuration,
        })
    }
}
impl ::std::fmt::Debug for IdentitySourceItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IdentitySourceItemBuilder");
        formatter.field("created_date", &self.created_date);
        formatter.field("details", &self.details);
        formatter.field("identity_source_id", &self.identity_source_id);
        formatter.field("last_updated_date", &self.last_updated_date);
        formatter.field("policy_store_id", &self.policy_store_id);
        formatter.field("principal_entity_type", &"*** Sensitive Data Redacted ***");
        formatter.field("configuration", &self.configuration);
        formatter.finish()
    }
}
