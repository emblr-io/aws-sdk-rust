// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicationStateInput {
    /// <p>The configurationId in Application Discovery Service that uniquely identifies the grouped application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
}
impl DescribeApplicationStateInput {
    /// <p>The configurationId in Application Discovery Service that uniquely identifies the grouped application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
}
impl DescribeApplicationStateInput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicationStateInput`](crate::operation::describe_application_state::DescribeApplicationStateInput).
    pub fn builder() -> crate::operation::describe_application_state::builders::DescribeApplicationStateInputBuilder {
        crate::operation::describe_application_state::builders::DescribeApplicationStateInputBuilder::default()
    }
}

/// A builder for [`DescribeApplicationStateInput`](crate::operation::describe_application_state::DescribeApplicationStateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicationStateInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
}
impl DescribeApplicationStateInputBuilder {
    /// <p>The configurationId in Application Discovery Service that uniquely identifies the grouped application.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configurationId in Application Discovery Service that uniquely identifies the grouped application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The configurationId in Application Discovery Service that uniquely identifies the grouped application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// Consumes the builder and constructs a [`DescribeApplicationStateInput`](crate::operation::describe_application_state::DescribeApplicationStateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_application_state::DescribeApplicationStateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_application_state::DescribeApplicationStateInput {
            application_id: self.application_id,
        })
    }
}
