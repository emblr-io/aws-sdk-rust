// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateOrganizationInput {
    /// <p>The AWS Directory Service directory ID.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>The organization alias.</p>
    pub alias: ::std::option::Option<::std::string::String>,
    /// <p>The idempotency token associated with the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The email domains to associate with the organization.</p>
    pub domains: ::std::option::Option<::std::vec::Vec<crate::types::Domain>>,
    /// <p>The Amazon Resource Name (ARN) of a customer managed key from AWS KMS.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>When <code>true</code>, allows organization interoperability between WorkMail and Microsoft Exchange. If <code>true</code>, you must include a AD Connector directory ID in the request.</p>
    pub enable_interoperability: ::std::option::Option<bool>,
}
impl CreateOrganizationInput {
    /// <p>The AWS Directory Service directory ID.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>The organization alias.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
    /// <p>The idempotency token associated with the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The email domains to associate with the organization.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domains.is_none()`.
    pub fn domains(&self) -> &[crate::types::Domain] {
        self.domains.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of a customer managed key from AWS KMS.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>When <code>true</code>, allows organization interoperability between WorkMail and Microsoft Exchange. If <code>true</code>, you must include a AD Connector directory ID in the request.</p>
    pub fn enable_interoperability(&self) -> ::std::option::Option<bool> {
        self.enable_interoperability
    }
}
impl CreateOrganizationInput {
    /// Creates a new builder-style object to manufacture [`CreateOrganizationInput`](crate::operation::create_organization::CreateOrganizationInput).
    pub fn builder() -> crate::operation::create_organization::builders::CreateOrganizationInputBuilder {
        crate::operation::create_organization::builders::CreateOrganizationInputBuilder::default()
    }
}

/// A builder for [`CreateOrganizationInput`](crate::operation::create_organization::CreateOrganizationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateOrganizationInputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) domains: ::std::option::Option<::std::vec::Vec<crate::types::Domain>>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) enable_interoperability: ::std::option::Option<bool>,
}
impl CreateOrganizationInputBuilder {
    /// <p>The AWS Directory Service directory ID.</p>
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS Directory Service directory ID.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The AWS Directory Service directory ID.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// <p>The organization alias.</p>
    /// This field is required.
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The organization alias.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The organization alias.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// <p>The idempotency token associated with the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The idempotency token associated with the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The idempotency token associated with the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `domains`.
    ///
    /// To override the contents of this collection use [`set_domains`](Self::set_domains).
    ///
    /// <p>The email domains to associate with the organization.</p>
    pub fn domains(mut self, input: crate::types::Domain) -> Self {
        let mut v = self.domains.unwrap_or_default();
        v.push(input);
        self.domains = ::std::option::Option::Some(v);
        self
    }
    /// <p>The email domains to associate with the organization.</p>
    pub fn set_domains(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Domain>>) -> Self {
        self.domains = input;
        self
    }
    /// <p>The email domains to associate with the organization.</p>
    pub fn get_domains(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Domain>> {
        &self.domains
    }
    /// <p>The Amazon Resource Name (ARN) of a customer managed key from AWS KMS.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a customer managed key from AWS KMS.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a customer managed key from AWS KMS.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// <p>When <code>true</code>, allows organization interoperability between WorkMail and Microsoft Exchange. If <code>true</code>, you must include a AD Connector directory ID in the request.</p>
    pub fn enable_interoperability(mut self, input: bool) -> Self {
        self.enable_interoperability = ::std::option::Option::Some(input);
        self
    }
    /// <p>When <code>true</code>, allows organization interoperability between WorkMail and Microsoft Exchange. If <code>true</code>, you must include a AD Connector directory ID in the request.</p>
    pub fn set_enable_interoperability(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_interoperability = input;
        self
    }
    /// <p>When <code>true</code>, allows organization interoperability between WorkMail and Microsoft Exchange. If <code>true</code>, you must include a AD Connector directory ID in the request.</p>
    pub fn get_enable_interoperability(&self) -> &::std::option::Option<bool> {
        &self.enable_interoperability
    }
    /// Consumes the builder and constructs a [`CreateOrganizationInput`](crate::operation::create_organization::CreateOrganizationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_organization::CreateOrganizationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_organization::CreateOrganizationInput {
            directory_id: self.directory_id,
            alias: self.alias,
            client_token: self.client_token,
            domains: self.domains,
            kms_key_arn: self.kms_key_arn,
            enable_interoperability: self.enable_interoperability,
        })
    }
}
