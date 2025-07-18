// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteFilterInput {
    /// <p>The ARN of the filter to delete.</p>
    pub filter_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteFilterInput {
    /// <p>The ARN of the filter to delete.</p>
    pub fn filter_arn(&self) -> ::std::option::Option<&str> {
        self.filter_arn.as_deref()
    }
}
impl DeleteFilterInput {
    /// Creates a new builder-style object to manufacture [`DeleteFilterInput`](crate::operation::delete_filter::DeleteFilterInput).
    pub fn builder() -> crate::operation::delete_filter::builders::DeleteFilterInputBuilder {
        crate::operation::delete_filter::builders::DeleteFilterInputBuilder::default()
    }
}

/// A builder for [`DeleteFilterInput`](crate::operation::delete_filter::DeleteFilterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteFilterInputBuilder {
    pub(crate) filter_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteFilterInputBuilder {
    /// <p>The ARN of the filter to delete.</p>
    /// This field is required.
    pub fn filter_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the filter to delete.</p>
    pub fn set_filter_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_arn = input;
        self
    }
    /// <p>The ARN of the filter to delete.</p>
    pub fn get_filter_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_arn
    }
    /// Consumes the builder and constructs a [`DeleteFilterInput`](crate::operation::delete_filter::DeleteFilterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_filter::DeleteFilterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_filter::DeleteFilterInput { filter_arn: self.filter_arn })
    }
}
