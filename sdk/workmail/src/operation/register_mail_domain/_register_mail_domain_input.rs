// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegisterMailDomainInput {
    /// <p>Idempotency token used when retrying requests.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The WorkMail organization under which you're creating the domain.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the mail domain to create in WorkMail and SES.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
}
impl RegisterMailDomainInput {
    /// <p>Idempotency token used when retrying requests.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The WorkMail organization under which you're creating the domain.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The name of the mail domain to create in WorkMail and SES.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
}
impl RegisterMailDomainInput {
    /// Creates a new builder-style object to manufacture [`RegisterMailDomainInput`](crate::operation::register_mail_domain::RegisterMailDomainInput).
    pub fn builder() -> crate::operation::register_mail_domain::builders::RegisterMailDomainInputBuilder {
        crate::operation::register_mail_domain::builders::RegisterMailDomainInputBuilder::default()
    }
}

/// A builder for [`RegisterMailDomainInput`](crate::operation::register_mail_domain::RegisterMailDomainInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegisterMailDomainInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
}
impl RegisterMailDomainInputBuilder {
    /// <p>Idempotency token used when retrying requests.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Idempotency token used when retrying requests.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Idempotency token used when retrying requests.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The WorkMail organization under which you're creating the domain.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The WorkMail organization under which you're creating the domain.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The WorkMail organization under which you're creating the domain.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The name of the mail domain to create in WorkMail and SES.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the mail domain to create in WorkMail and SES.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the mail domain to create in WorkMail and SES.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// Consumes the builder and constructs a [`RegisterMailDomainInput`](crate::operation::register_mail_domain::RegisterMailDomainInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::register_mail_domain::RegisterMailDomainInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::register_mail_domain::RegisterMailDomainInput {
            client_token: self.client_token,
            organization_id: self.organization_id,
            domain_name: self.domain_name,
        })
    }
}
