// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that describes a filter for application assignments.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListApplicationAssignmentsFilter {
    /// <p>The ARN of an application.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
}
impl ListApplicationAssignmentsFilter {
    /// <p>The ARN of an application.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
}
impl ListApplicationAssignmentsFilter {
    /// Creates a new builder-style object to manufacture [`ListApplicationAssignmentsFilter`](crate::types::ListApplicationAssignmentsFilter).
    pub fn builder() -> crate::types::builders::ListApplicationAssignmentsFilterBuilder {
        crate::types::builders::ListApplicationAssignmentsFilterBuilder::default()
    }
}

/// A builder for [`ListApplicationAssignmentsFilter`](crate::types::ListApplicationAssignmentsFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListApplicationAssignmentsFilterBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
}
impl ListApplicationAssignmentsFilterBuilder {
    /// <p>The ARN of an application.</p>
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of an application.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The ARN of an application.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// Consumes the builder and constructs a [`ListApplicationAssignmentsFilter`](crate::types::ListApplicationAssignmentsFilter).
    pub fn build(self) -> crate::types::ListApplicationAssignmentsFilter {
        crate::types::ListApplicationAssignmentsFilter {
            application_arn: self.application_arn,
        }
    }
}
