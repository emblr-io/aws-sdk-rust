// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the objective that a common control supports.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociatedObjectiveSummary {
    /// <p>The Amazon Resource Name (ARN) of the related objective.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the related objective.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl AssociatedObjectiveSummary {
    /// <p>The Amazon Resource Name (ARN) of the related objective.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the related objective.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl AssociatedObjectiveSummary {
    /// Creates a new builder-style object to manufacture [`AssociatedObjectiveSummary`](crate::types::AssociatedObjectiveSummary).
    pub fn builder() -> crate::types::builders::AssociatedObjectiveSummaryBuilder {
        crate::types::builders::AssociatedObjectiveSummaryBuilder::default()
    }
}

/// A builder for [`AssociatedObjectiveSummary`](crate::types::AssociatedObjectiveSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociatedObjectiveSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl AssociatedObjectiveSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the related objective.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the related objective.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the related objective.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the related objective.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the related objective.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the related objective.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`AssociatedObjectiveSummary`](crate::types::AssociatedObjectiveSummary).
    pub fn build(self) -> crate::types::AssociatedObjectiveSummary {
        crate::types::AssociatedObjectiveSummary {
            arn: self.arn,
            name: self.name,
        }
    }
}
