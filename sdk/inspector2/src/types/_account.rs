// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An Amazon Web Services account within your environment that Amazon Inspector has been enabled for.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Account {
    /// <p>The ID of the Amazon Web Services account.</p>
    pub account_id: ::std::string::String,
    /// <p>The status of Amazon Inspector for the account.</p>
    pub status: crate::types::Status,
    /// <p>Details of the status of Amazon Inspector scans by resource type.</p>
    pub resource_status: ::std::option::Option<crate::types::ResourceStatus>,
}
impl Account {
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn account_id(&self) -> &str {
        use std::ops::Deref;
        self.account_id.deref()
    }
    /// <p>The status of Amazon Inspector for the account.</p>
    pub fn status(&self) -> &crate::types::Status {
        &self.status
    }
    /// <p>Details of the status of Amazon Inspector scans by resource type.</p>
    pub fn resource_status(&self) -> ::std::option::Option<&crate::types::ResourceStatus> {
        self.resource_status.as_ref()
    }
}
impl Account {
    /// Creates a new builder-style object to manufacture [`Account`](crate::types::Account).
    pub fn builder() -> crate::types::builders::AccountBuilder {
        crate::types::builders::AccountBuilder::default()
    }
}

/// A builder for [`Account`](crate::types::Account).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) resource_status: ::std::option::Option<crate::types::ResourceStatus>,
}
impl AccountBuilder {
    /// <p>The ID of the Amazon Web Services account.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The status of Amazon Inspector for the account.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of Amazon Inspector for the account.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of Amazon Inspector for the account.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>Details of the status of Amazon Inspector scans by resource type.</p>
    /// This field is required.
    pub fn resource_status(mut self, input: crate::types::ResourceStatus) -> Self {
        self.resource_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details of the status of Amazon Inspector scans by resource type.</p>
    pub fn set_resource_status(mut self, input: ::std::option::Option<crate::types::ResourceStatus>) -> Self {
        self.resource_status = input;
        self
    }
    /// <p>Details of the status of Amazon Inspector scans by resource type.</p>
    pub fn get_resource_status(&self) -> &::std::option::Option<crate::types::ResourceStatus> {
        &self.resource_status
    }
    /// Consumes the builder and constructs a [`Account`](crate::types::Account).
    /// This method will fail if any of the following fields are not set:
    /// - [`account_id`](crate::types::builders::AccountBuilder::account_id)
    /// - [`status`](crate::types::builders::AccountBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::Account, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Account {
            account_id: self.account_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "account_id",
                    "account_id was not specified but it is required when building Account",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building Account",
                )
            })?,
            resource_status: self.resource_status,
        })
    }
}
