// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePortalInput {
    /// <p>The ID of the portal.</p>
    pub portal_id: ::std::option::Option<::std::string::String>,
}
impl DescribePortalInput {
    /// <p>The ID of the portal.</p>
    pub fn portal_id(&self) -> ::std::option::Option<&str> {
        self.portal_id.as_deref()
    }
}
impl DescribePortalInput {
    /// Creates a new builder-style object to manufacture [`DescribePortalInput`](crate::operation::describe_portal::DescribePortalInput).
    pub fn builder() -> crate::operation::describe_portal::builders::DescribePortalInputBuilder {
        crate::operation::describe_portal::builders::DescribePortalInputBuilder::default()
    }
}

/// A builder for [`DescribePortalInput`](crate::operation::describe_portal::DescribePortalInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePortalInputBuilder {
    pub(crate) portal_id: ::std::option::Option<::std::string::String>,
}
impl DescribePortalInputBuilder {
    /// <p>The ID of the portal.</p>
    /// This field is required.
    pub fn portal_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.portal_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the portal.</p>
    pub fn set_portal_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.portal_id = input;
        self
    }
    /// <p>The ID of the portal.</p>
    pub fn get_portal_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.portal_id
    }
    /// Consumes the builder and constructs a [`DescribePortalInput`](crate::operation::describe_portal::DescribePortalInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_portal::DescribePortalInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_portal::DescribePortalInput { portal_id: self.portal_id })
    }
}
