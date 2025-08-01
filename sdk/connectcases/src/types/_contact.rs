// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents an Amazon Connect contact object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Contact {
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub contact_arn: ::std::string::String,
}
impl Contact {
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub fn contact_arn(&self) -> &str {
        use std::ops::Deref;
        self.contact_arn.deref()
    }
}
impl Contact {
    /// Creates a new builder-style object to manufacture [`Contact`](crate::types::Contact).
    pub fn builder() -> crate::types::builders::ContactBuilder {
        crate::types::builders::ContactBuilder::default()
    }
}

/// A builder for [`Contact`](crate::types::Contact).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContactBuilder {
    pub(crate) contact_arn: ::std::option::Option<::std::string::String>,
}
impl ContactBuilder {
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    /// This field is required.
    pub fn contact_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub fn set_contact_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_arn = input;
        self
    }
    /// <p>A unique identifier of a contact in Amazon Connect.</p>
    pub fn get_contact_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_arn
    }
    /// Consumes the builder and constructs a [`Contact`](crate::types::Contact).
    /// This method will fail if any of the following fields are not set:
    /// - [`contact_arn`](crate::types::builders::ContactBuilder::contact_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::Contact, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Contact {
            contact_arn: self.contact_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "contact_arn",
                    "contact_arn was not specified but it is required when building Contact",
                )
            })?,
        })
    }
}
