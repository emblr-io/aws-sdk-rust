// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePortalInput {
    /// <p>The ARN of the web portal.</p>
    pub portal_arn: ::std::option::Option<::std::string::String>,
}
impl DeletePortalInput {
    /// <p>The ARN of the web portal.</p>
    pub fn portal_arn(&self) -> ::std::option::Option<&str> {
        self.portal_arn.as_deref()
    }
}
impl DeletePortalInput {
    /// Creates a new builder-style object to manufacture [`DeletePortalInput`](crate::operation::delete_portal::DeletePortalInput).
    pub fn builder() -> crate::operation::delete_portal::builders::DeletePortalInputBuilder {
        crate::operation::delete_portal::builders::DeletePortalInputBuilder::default()
    }
}

/// A builder for [`DeletePortalInput`](crate::operation::delete_portal::DeletePortalInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePortalInputBuilder {
    pub(crate) portal_arn: ::std::option::Option<::std::string::String>,
}
impl DeletePortalInputBuilder {
    /// <p>The ARN of the web portal.</p>
    /// This field is required.
    pub fn portal_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.portal_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the web portal.</p>
    pub fn set_portal_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.portal_arn = input;
        self
    }
    /// <p>The ARN of the web portal.</p>
    pub fn get_portal_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.portal_arn
    }
    /// Consumes the builder and constructs a [`DeletePortalInput`](crate::operation::delete_portal::DeletePortalInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_portal::DeletePortalInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_portal::DeletePortalInput { portal_arn: self.portal_arn })
    }
}
