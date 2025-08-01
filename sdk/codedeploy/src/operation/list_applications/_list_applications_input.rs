// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>ListApplications</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListApplicationsInput {
    /// <p>An identifier returned from the previous list applications call. It can be used to return the next set of applications in the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListApplicationsInput {
    /// <p>An identifier returned from the previous list applications call. It can be used to return the next set of applications in the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListApplicationsInput {
    /// Creates a new builder-style object to manufacture [`ListApplicationsInput`](crate::operation::list_applications::ListApplicationsInput).
    pub fn builder() -> crate::operation::list_applications::builders::ListApplicationsInputBuilder {
        crate::operation::list_applications::builders::ListApplicationsInputBuilder::default()
    }
}

/// A builder for [`ListApplicationsInput`](crate::operation::list_applications::ListApplicationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListApplicationsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListApplicationsInputBuilder {
    /// <p>An identifier returned from the previous list applications call. It can be used to return the next set of applications in the list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier returned from the previous list applications call. It can be used to return the next set of applications in the list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An identifier returned from the previous list applications call. It can be used to return the next set of applications in the list.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListApplicationsInput`](crate::operation::list_applications::ListApplicationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_applications::ListApplicationsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_applications::ListApplicationsInput { next_token: self.next_token })
    }
}
