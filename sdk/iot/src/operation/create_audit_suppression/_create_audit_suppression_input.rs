// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAuditSuppressionInput {
    /// <p>An audit check name. Checks must be enabled for your account. (Use <code>DescribeAccountAuditConfiguration</code> to see the list of all checks, including those that are enabled or use <code>UpdateAccountAuditConfiguration</code> to select which checks are enabled.)</p>
    pub check_name: ::std::option::Option<::std::string::String>,
    /// <p>Information that identifies the noncompliant resource.</p>
    pub resource_identifier: ::std::option::Option<crate::types::ResourceIdentifier>,
    /// <p>The epoch timestamp in seconds at which this suppression expires.</p>
    pub expiration_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates whether a suppression should exist indefinitely or not.</p>
    pub suppress_indefinitely: ::std::option::Option<bool>,
    /// <p>The description of the audit suppression.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Each audit supression must have a unique client request token. If you try to create a new audit suppression with the same token as one that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateAuditSuppressionInput {
    /// <p>An audit check name. Checks must be enabled for your account. (Use <code>DescribeAccountAuditConfiguration</code> to see the list of all checks, including those that are enabled or use <code>UpdateAccountAuditConfiguration</code> to select which checks are enabled.)</p>
    pub fn check_name(&self) -> ::std::option::Option<&str> {
        self.check_name.as_deref()
    }
    /// <p>Information that identifies the noncompliant resource.</p>
    pub fn resource_identifier(&self) -> ::std::option::Option<&crate::types::ResourceIdentifier> {
        self.resource_identifier.as_ref()
    }
    /// <p>The epoch timestamp in seconds at which this suppression expires.</p>
    pub fn expiration_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.expiration_date.as_ref()
    }
    /// <p>Indicates whether a suppression should exist indefinitely or not.</p>
    pub fn suppress_indefinitely(&self) -> ::std::option::Option<bool> {
        self.suppress_indefinitely
    }
    /// <p>The description of the audit suppression.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Each audit supression must have a unique client request token. If you try to create a new audit suppression with the same token as one that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl CreateAuditSuppressionInput {
    /// Creates a new builder-style object to manufacture [`CreateAuditSuppressionInput`](crate::operation::create_audit_suppression::CreateAuditSuppressionInput).
    pub fn builder() -> crate::operation::create_audit_suppression::builders::CreateAuditSuppressionInputBuilder {
        crate::operation::create_audit_suppression::builders::CreateAuditSuppressionInputBuilder::default()
    }
}

/// A builder for [`CreateAuditSuppressionInput`](crate::operation::create_audit_suppression::CreateAuditSuppressionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAuditSuppressionInputBuilder {
    pub(crate) check_name: ::std::option::Option<::std::string::String>,
    pub(crate) resource_identifier: ::std::option::Option<crate::types::ResourceIdentifier>,
    pub(crate) expiration_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) suppress_indefinitely: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateAuditSuppressionInputBuilder {
    /// <p>An audit check name. Checks must be enabled for your account. (Use <code>DescribeAccountAuditConfiguration</code> to see the list of all checks, including those that are enabled or use <code>UpdateAccountAuditConfiguration</code> to select which checks are enabled.)</p>
    /// This field is required.
    pub fn check_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.check_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An audit check name. Checks must be enabled for your account. (Use <code>DescribeAccountAuditConfiguration</code> to see the list of all checks, including those that are enabled or use <code>UpdateAccountAuditConfiguration</code> to select which checks are enabled.)</p>
    pub fn set_check_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.check_name = input;
        self
    }
    /// <p>An audit check name. Checks must be enabled for your account. (Use <code>DescribeAccountAuditConfiguration</code> to see the list of all checks, including those that are enabled or use <code>UpdateAccountAuditConfiguration</code> to select which checks are enabled.)</p>
    pub fn get_check_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.check_name
    }
    /// <p>Information that identifies the noncompliant resource.</p>
    /// This field is required.
    pub fn resource_identifier(mut self, input: crate::types::ResourceIdentifier) -> Self {
        self.resource_identifier = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information that identifies the noncompliant resource.</p>
    pub fn set_resource_identifier(mut self, input: ::std::option::Option<crate::types::ResourceIdentifier>) -> Self {
        self.resource_identifier = input;
        self
    }
    /// <p>Information that identifies the noncompliant resource.</p>
    pub fn get_resource_identifier(&self) -> &::std::option::Option<crate::types::ResourceIdentifier> {
        &self.resource_identifier
    }
    /// <p>The epoch timestamp in seconds at which this suppression expires.</p>
    pub fn expiration_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.expiration_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The epoch timestamp in seconds at which this suppression expires.</p>
    pub fn set_expiration_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.expiration_date = input;
        self
    }
    /// <p>The epoch timestamp in seconds at which this suppression expires.</p>
    pub fn get_expiration_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.expiration_date
    }
    /// <p>Indicates whether a suppression should exist indefinitely or not.</p>
    pub fn suppress_indefinitely(mut self, input: bool) -> Self {
        self.suppress_indefinitely = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether a suppression should exist indefinitely or not.</p>
    pub fn set_suppress_indefinitely(mut self, input: ::std::option::Option<bool>) -> Self {
        self.suppress_indefinitely = input;
        self
    }
    /// <p>Indicates whether a suppression should exist indefinitely or not.</p>
    pub fn get_suppress_indefinitely(&self) -> &::std::option::Option<bool> {
        &self.suppress_indefinitely
    }
    /// <p>The description of the audit suppression.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the audit suppression.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the audit suppression.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Each audit supression must have a unique client request token. If you try to create a new audit suppression with the same token as one that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    /// This field is required.
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Each audit supression must have a unique client request token. If you try to create a new audit suppression with the same token as one that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Each audit supression must have a unique client request token. If you try to create a new audit suppression with the same token as one that already exists, an exception occurs. If you omit this value, Amazon Web Services SDKs will automatically generate a unique client request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`CreateAuditSuppressionInput`](crate::operation::create_audit_suppression::CreateAuditSuppressionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_audit_suppression::CreateAuditSuppressionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_audit_suppression::CreateAuditSuppressionInput {
            check_name: self.check_name,
            resource_identifier: self.resource_identifier,
            expiration_date: self.expiration_date,
            suppress_indefinitely: self.suppress_indefinitely,
            description: self.description,
            client_request_token: self.client_request_token,
        })
    }
}
