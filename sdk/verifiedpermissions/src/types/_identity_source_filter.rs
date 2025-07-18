// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that defines characteristics of an identity source that you can use to filter.</p>
/// <p>This data type is a request parameter for the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListIdentityStores.html">ListIdentityStores</a> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct IdentitySourceFilter {
    /// <p>The Cedar entity type of the principals returned by the identity provider (IdP) associated with this identity source.</p>
    pub principal_entity_type: ::std::option::Option<::std::string::String>,
}
impl IdentitySourceFilter {
    /// <p>The Cedar entity type of the principals returned by the identity provider (IdP) associated with this identity source.</p>
    pub fn principal_entity_type(&self) -> ::std::option::Option<&str> {
        self.principal_entity_type.as_deref()
    }
}
impl ::std::fmt::Debug for IdentitySourceFilter {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IdentitySourceFilter");
        formatter.field("principal_entity_type", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl IdentitySourceFilter {
    /// Creates a new builder-style object to manufacture [`IdentitySourceFilter`](crate::types::IdentitySourceFilter).
    pub fn builder() -> crate::types::builders::IdentitySourceFilterBuilder {
        crate::types::builders::IdentitySourceFilterBuilder::default()
    }
}

/// A builder for [`IdentitySourceFilter`](crate::types::IdentitySourceFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct IdentitySourceFilterBuilder {
    pub(crate) principal_entity_type: ::std::option::Option<::std::string::String>,
}
impl IdentitySourceFilterBuilder {
    /// <p>The Cedar entity type of the principals returned by the identity provider (IdP) associated with this identity source.</p>
    pub fn principal_entity_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal_entity_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Cedar entity type of the principals returned by the identity provider (IdP) associated with this identity source.</p>
    pub fn set_principal_entity_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal_entity_type = input;
        self
    }
    /// <p>The Cedar entity type of the principals returned by the identity provider (IdP) associated with this identity source.</p>
    pub fn get_principal_entity_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal_entity_type
    }
    /// Consumes the builder and constructs a [`IdentitySourceFilter`](crate::types::IdentitySourceFilter).
    pub fn build(self) -> crate::types::IdentitySourceFilter {
        crate::types::IdentitySourceFilter {
            principal_entity_type: self.principal_entity_type,
        }
    }
}
impl ::std::fmt::Debug for IdentitySourceFilterBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IdentitySourceFilterBuilder");
        formatter.field("principal_entity_type", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
