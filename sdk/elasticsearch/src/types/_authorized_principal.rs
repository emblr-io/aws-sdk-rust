// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an account or service that has access to an Amazon OpenSearch Service domain through the use of an interface VPC endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AuthorizedPrincipal {
    /// <p>The type of principal.</p>
    pub principal_type: ::std::option::Option<crate::types::PrincipalType>,
    /// <p>The IAM principal that is allowed access to the domain.</p>
    pub principal: ::std::option::Option<::std::string::String>,
}
impl AuthorizedPrincipal {
    /// <p>The type of principal.</p>
    pub fn principal_type(&self) -> ::std::option::Option<&crate::types::PrincipalType> {
        self.principal_type.as_ref()
    }
    /// <p>The IAM principal that is allowed access to the domain.</p>
    pub fn principal(&self) -> ::std::option::Option<&str> {
        self.principal.as_deref()
    }
}
impl AuthorizedPrincipal {
    /// Creates a new builder-style object to manufacture [`AuthorizedPrincipal`](crate::types::AuthorizedPrincipal).
    pub fn builder() -> crate::types::builders::AuthorizedPrincipalBuilder {
        crate::types::builders::AuthorizedPrincipalBuilder::default()
    }
}

/// A builder for [`AuthorizedPrincipal`](crate::types::AuthorizedPrincipal).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AuthorizedPrincipalBuilder {
    pub(crate) principal_type: ::std::option::Option<crate::types::PrincipalType>,
    pub(crate) principal: ::std::option::Option<::std::string::String>,
}
impl AuthorizedPrincipalBuilder {
    /// <p>The type of principal.</p>
    pub fn principal_type(mut self, input: crate::types::PrincipalType) -> Self {
        self.principal_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of principal.</p>
    pub fn set_principal_type(mut self, input: ::std::option::Option<crate::types::PrincipalType>) -> Self {
        self.principal_type = input;
        self
    }
    /// <p>The type of principal.</p>
    pub fn get_principal_type(&self) -> &::std::option::Option<crate::types::PrincipalType> {
        &self.principal_type
    }
    /// <p>The IAM principal that is allowed access to the domain.</p>
    pub fn principal(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.principal = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM principal that is allowed access to the domain.</p>
    pub fn set_principal(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.principal = input;
        self
    }
    /// <p>The IAM principal that is allowed access to the domain.</p>
    pub fn get_principal(&self) -> &::std::option::Option<::std::string::String> {
        &self.principal
    }
    /// Consumes the builder and constructs a [`AuthorizedPrincipal`](crate::types::AuthorizedPrincipal).
    pub fn build(self) -> crate::types::AuthorizedPrincipal {
        crate::types::AuthorizedPrincipal {
            principal_type: self.principal_type,
            principal: self.principal,
        }
    }
}
