// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to describe one or more applications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeApplicationsInput {
    /// <p>If specified, AWS Elastic Beanstalk restricts the returned descriptions to only include those with the specified names.</p>
    pub application_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeApplicationsInput {
    /// <p>If specified, AWS Elastic Beanstalk restricts the returned descriptions to only include those with the specified names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.application_names.is_none()`.
    pub fn application_names(&self) -> &[::std::string::String] {
        self.application_names.as_deref().unwrap_or_default()
    }
}
impl DescribeApplicationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeApplicationsInput`](crate::operation::describe_applications::DescribeApplicationsInput).
    pub fn builder() -> crate::operation::describe_applications::builders::DescribeApplicationsInputBuilder {
        crate::operation::describe_applications::builders::DescribeApplicationsInputBuilder::default()
    }
}

/// A builder for [`DescribeApplicationsInput`](crate::operation::describe_applications::DescribeApplicationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeApplicationsInputBuilder {
    pub(crate) application_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DescribeApplicationsInputBuilder {
    /// Appends an item to `application_names`.
    ///
    /// To override the contents of this collection use [`set_application_names`](Self::set_application_names).
    ///
    /// <p>If specified, AWS Elastic Beanstalk restricts the returned descriptions to only include those with the specified names.</p>
    pub fn application_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.application_names.unwrap_or_default();
        v.push(input.into());
        self.application_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>If specified, AWS Elastic Beanstalk restricts the returned descriptions to only include those with the specified names.</p>
    pub fn set_application_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.application_names = input;
        self
    }
    /// <p>If specified, AWS Elastic Beanstalk restricts the returned descriptions to only include those with the specified names.</p>
    pub fn get_application_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.application_names
    }
    /// Consumes the builder and constructs a [`DescribeApplicationsInput`](crate::operation::describe_applications::DescribeApplicationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_applications::DescribeApplicationsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_applications::DescribeApplicationsInput {
            application_names: self.application_names,
        })
    }
}
