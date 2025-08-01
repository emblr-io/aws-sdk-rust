// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInsightInput {
    /// <p>The ID of the insight.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the member account in the organization.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
}
impl DescribeInsightInput {
    /// <p>The ID of the insight.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The ID of the member account in the organization.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
}
impl DescribeInsightInput {
    /// Creates a new builder-style object to manufacture [`DescribeInsightInput`](crate::operation::describe_insight::DescribeInsightInput).
    pub fn builder() -> crate::operation::describe_insight::builders::DescribeInsightInputBuilder {
        crate::operation::describe_insight::builders::DescribeInsightInputBuilder::default()
    }
}

/// A builder for [`DescribeInsightInput`](crate::operation::describe_insight::DescribeInsightInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInsightInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
}
impl DescribeInsightInputBuilder {
    /// <p>The ID of the insight.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the insight.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the insight.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ID of the member account in the organization.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the member account in the organization.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The ID of the member account in the organization.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// Consumes the builder and constructs a [`DescribeInsightInput`](crate::operation::describe_insight::DescribeInsightInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_insight::DescribeInsightInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_insight::DescribeInsightInput {
            id: self.id,
            account_id: self.account_id,
        })
    }
}
