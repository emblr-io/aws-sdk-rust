// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateDomainUnitInput {
    /// <p>The ID of the domain where you want to crate a domain unit.</p>
    pub domain_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the domain unit.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the parent domain unit.</p>
    pub parent_domain_unit_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The description of the domain unit.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateDomainUnitInput {
    /// <p>The ID of the domain where you want to crate a domain unit.</p>
    pub fn domain_identifier(&self) -> ::std::option::Option<&str> {
        self.domain_identifier.as_deref()
    }
    /// <p>The name of the domain unit.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn parent_domain_unit_identifier(&self) -> ::std::option::Option<&str> {
        self.parent_domain_unit_identifier.as_deref()
    }
    /// <p>The description of the domain unit.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::std::fmt::Debug for CreateDomainUnitInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateDomainUnitInput");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("parent_domain_unit_identifier", &self.parent_domain_unit_identifier);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
impl CreateDomainUnitInput {
    /// Creates a new builder-style object to manufacture [`CreateDomainUnitInput`](crate::operation::create_domain_unit::CreateDomainUnitInput).
    pub fn builder() -> crate::operation::create_domain_unit::builders::CreateDomainUnitInputBuilder {
        crate::operation::create_domain_unit::builders::CreateDomainUnitInputBuilder::default()
    }
}

/// A builder for [`CreateDomainUnitInput`](crate::operation::create_domain_unit::CreateDomainUnitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateDomainUnitInputBuilder {
    pub(crate) domain_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) parent_domain_unit_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateDomainUnitInputBuilder {
    /// <p>The ID of the domain where you want to crate a domain unit.</p>
    /// This field is required.
    pub fn domain_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the domain where you want to crate a domain unit.</p>
    pub fn set_domain_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_identifier = input;
        self
    }
    /// <p>The ID of the domain where you want to crate a domain unit.</p>
    pub fn get_domain_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_identifier
    }
    /// <p>The name of the domain unit.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the domain unit.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the domain unit.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ID of the parent domain unit.</p>
    /// This field is required.
    pub fn parent_domain_unit_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_domain_unit_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn set_parent_domain_unit_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_domain_unit_identifier = input;
        self
    }
    /// <p>The ID of the parent domain unit.</p>
    pub fn get_parent_domain_unit_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_domain_unit_identifier
    }
    /// <p>The description of the domain unit.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the domain unit.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the domain unit.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that is provided to ensure the idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateDomainUnitInput`](crate::operation::create_domain_unit::CreateDomainUnitInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_domain_unit::CreateDomainUnitInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_domain_unit::CreateDomainUnitInput {
            domain_identifier: self.domain_identifier,
            name: self.name,
            parent_domain_unit_identifier: self.parent_domain_unit_identifier,
            description: self.description,
            client_token: self.client_token,
        })
    }
}
impl ::std::fmt::Debug for CreateDomainUnitInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateDomainUnitInputBuilder");
        formatter.field("domain_identifier", &self.domain_identifier);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("parent_domain_unit_identifier", &self.parent_domain_unit_identifier);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
