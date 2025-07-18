// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a time-based filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterTimestamp {
    /// <p>Include results after this timestamp.</p>
    pub after_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Include results before this timestamp.</p>
    pub before_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl FilterTimestamp {
    /// <p>Include results after this timestamp.</p>
    pub fn after_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.after_timestamp.as_ref()
    }
    /// <p>Include results before this timestamp.</p>
    pub fn before_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.before_timestamp.as_ref()
    }
}
impl FilterTimestamp {
    /// Creates a new builder-style object to manufacture [`FilterTimestamp`](crate::types::FilterTimestamp).
    pub fn builder() -> crate::types::builders::FilterTimestampBuilder {
        crate::types::builders::FilterTimestampBuilder::default()
    }
}

/// A builder for [`FilterTimestamp`](crate::types::FilterTimestamp).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterTimestampBuilder {
    pub(crate) after_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) before_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl FilterTimestampBuilder {
    /// <p>Include results after this timestamp.</p>
    pub fn after_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.after_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Include results after this timestamp.</p>
    pub fn set_after_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.after_timestamp = input;
        self
    }
    /// <p>Include results after this timestamp.</p>
    pub fn get_after_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.after_timestamp
    }
    /// <p>Include results before this timestamp.</p>
    pub fn before_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.before_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>Include results before this timestamp.</p>
    pub fn set_before_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.before_timestamp = input;
        self
    }
    /// <p>Include results before this timestamp.</p>
    pub fn get_before_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.before_timestamp
    }
    /// Consumes the builder and constructs a [`FilterTimestamp`](crate::types::FilterTimestamp).
    pub fn build(self) -> crate::types::FilterTimestamp {
        crate::types::FilterTimestamp {
            after_timestamp: self.after_timestamp,
            before_timestamp: self.before_timestamp,
        }
    }
}
