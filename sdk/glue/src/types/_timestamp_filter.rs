// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A timestamp filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimestampFilter {
    /// <p>The timestamp before which statistics should be included in the results.</p>
    pub recorded_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp after which statistics should be included in the results.</p>
    pub recorded_after: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TimestampFilter {
    /// <p>The timestamp before which statistics should be included in the results.</p>
    pub fn recorded_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.recorded_before.as_ref()
    }
    /// <p>The timestamp after which statistics should be included in the results.</p>
    pub fn recorded_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.recorded_after.as_ref()
    }
}
impl TimestampFilter {
    /// Creates a new builder-style object to manufacture [`TimestampFilter`](crate::types::TimestampFilter).
    pub fn builder() -> crate::types::builders::TimestampFilterBuilder {
        crate::types::builders::TimestampFilterBuilder::default()
    }
}

/// A builder for [`TimestampFilter`](crate::types::TimestampFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimestampFilterBuilder {
    pub(crate) recorded_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) recorded_after: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl TimestampFilterBuilder {
    /// <p>The timestamp before which statistics should be included in the results.</p>
    pub fn recorded_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.recorded_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp before which statistics should be included in the results.</p>
    pub fn set_recorded_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.recorded_before = input;
        self
    }
    /// <p>The timestamp before which statistics should be included in the results.</p>
    pub fn get_recorded_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.recorded_before
    }
    /// <p>The timestamp after which statistics should be included in the results.</p>
    pub fn recorded_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.recorded_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp after which statistics should be included in the results.</p>
    pub fn set_recorded_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.recorded_after = input;
        self
    }
    /// <p>The timestamp after which statistics should be included in the results.</p>
    pub fn get_recorded_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.recorded_after
    }
    /// Consumes the builder and constructs a [`TimestampFilter`](crate::types::TimestampFilter).
    pub fn build(self) -> crate::types::TimestampFilter {
        crate::types::TimestampFilter {
            recorded_before: self.recorded_before,
            recorded_after: self.recorded_after,
        }
    }
}
