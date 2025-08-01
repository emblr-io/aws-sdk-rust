// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The objective resource that's being used as a filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectiveResourceFilter {
    /// <p>The Amazon Resource Name (ARN) of the objective.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl ObjectiveResourceFilter {
    /// <p>The Amazon Resource Name (ARN) of the objective.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl ObjectiveResourceFilter {
    /// Creates a new builder-style object to manufacture [`ObjectiveResourceFilter`](crate::types::ObjectiveResourceFilter).
    pub fn builder() -> crate::types::builders::ObjectiveResourceFilterBuilder {
        crate::types::builders::ObjectiveResourceFilterBuilder::default()
    }
}

/// A builder for [`ObjectiveResourceFilter`](crate::types::ObjectiveResourceFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObjectiveResourceFilterBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl ObjectiveResourceFilterBuilder {
    /// <p>The Amazon Resource Name (ARN) of the objective.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the objective.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the objective.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`ObjectiveResourceFilter`](crate::types::ObjectiveResourceFilter).
    pub fn build(self) -> crate::types::ObjectiveResourceFilter {
        crate::types::ObjectiveResourceFilter { arn: self.arn }
    }
}
