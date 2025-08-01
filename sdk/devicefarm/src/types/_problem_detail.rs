// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a problem detail.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProblemDetail {
    /// <p>The problem detail's ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The problem detail's name.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl ProblemDetail {
    /// <p>The problem detail's ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The problem detail's name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ProblemDetail {
    /// Creates a new builder-style object to manufacture [`ProblemDetail`](crate::types::ProblemDetail).
    pub fn builder() -> crate::types::builders::ProblemDetailBuilder {
        crate::types::builders::ProblemDetailBuilder::default()
    }
}

/// A builder for [`ProblemDetail`](crate::types::ProblemDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProblemDetailBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl ProblemDetailBuilder {
    /// <p>The problem detail's ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The problem detail's ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The problem detail's ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The problem detail's name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The problem detail's name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The problem detail's name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`ProblemDetail`](crate::types::ProblemDetail).
    pub fn build(self) -> crate::types::ProblemDetail {
        crate::types::ProblemDetail {
            arn: self.arn,
            name: self.name,
        }
    }
}
