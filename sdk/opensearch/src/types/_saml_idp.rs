// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The SAML identity povider information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SamlIdp {
    /// <p>The metadata of the SAML application, in XML format.</p>
    pub metadata_content: ::std::string::String,
    /// <p>The unique entity ID of the application in the SAML identity provider.</p>
    pub entity_id: ::std::string::String,
}
impl SamlIdp {
    /// <p>The metadata of the SAML application, in XML format.</p>
    pub fn metadata_content(&self) -> &str {
        use std::ops::Deref;
        self.metadata_content.deref()
    }
    /// <p>The unique entity ID of the application in the SAML identity provider.</p>
    pub fn entity_id(&self) -> &str {
        use std::ops::Deref;
        self.entity_id.deref()
    }
}
impl SamlIdp {
    /// Creates a new builder-style object to manufacture [`SamlIdp`](crate::types::SamlIdp).
    pub fn builder() -> crate::types::builders::SamlIdpBuilder {
        crate::types::builders::SamlIdpBuilder::default()
    }
}

/// A builder for [`SamlIdp`](crate::types::SamlIdp).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SamlIdpBuilder {
    pub(crate) metadata_content: ::std::option::Option<::std::string::String>,
    pub(crate) entity_id: ::std::option::Option<::std::string::String>,
}
impl SamlIdpBuilder {
    /// <p>The metadata of the SAML application, in XML format.</p>
    /// This field is required.
    pub fn metadata_content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metadata_content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metadata of the SAML application, in XML format.</p>
    pub fn set_metadata_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metadata_content = input;
        self
    }
    /// <p>The metadata of the SAML application, in XML format.</p>
    pub fn get_metadata_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.metadata_content
    }
    /// <p>The unique entity ID of the application in the SAML identity provider.</p>
    /// This field is required.
    pub fn entity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique entity ID of the application in the SAML identity provider.</p>
    pub fn set_entity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id = input;
        self
    }
    /// <p>The unique entity ID of the application in the SAML identity provider.</p>
    pub fn get_entity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id
    }
    /// Consumes the builder and constructs a [`SamlIdp`](crate::types::SamlIdp).
    /// This method will fail if any of the following fields are not set:
    /// - [`metadata_content`](crate::types::builders::SamlIdpBuilder::metadata_content)
    /// - [`entity_id`](crate::types::builders::SamlIdpBuilder::entity_id)
    pub fn build(self) -> ::std::result::Result<crate::types::SamlIdp, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SamlIdp {
            metadata_content: self.metadata_content.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "metadata_content",
                    "metadata_content was not specified but it is required when building SamlIdp",
                )
            })?,
            entity_id: self.entity_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entity_id",
                    "entity_id was not specified but it is required when building SamlIdp",
                )
            })?,
        })
    }
}
