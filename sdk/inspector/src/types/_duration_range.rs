// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This data type is used in the <code>AssessmentTemplateFilter</code> data type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DurationRange {
    /// <p>The minimum value of the duration range. Must be greater than zero.</p>
    pub min_seconds: ::std::option::Option<i32>,
    /// <p>The maximum value of the duration range. Must be less than or equal to 604800 seconds (1 week).</p>
    pub max_seconds: ::std::option::Option<i32>,
}
impl DurationRange {
    /// <p>The minimum value of the duration range. Must be greater than zero.</p>
    pub fn min_seconds(&self) -> ::std::option::Option<i32> {
        self.min_seconds
    }
    /// <p>The maximum value of the duration range. Must be less than or equal to 604800 seconds (1 week).</p>
    pub fn max_seconds(&self) -> ::std::option::Option<i32> {
        self.max_seconds
    }
}
impl DurationRange {
    /// Creates a new builder-style object to manufacture [`DurationRange`](crate::types::DurationRange).
    pub fn builder() -> crate::types::builders::DurationRangeBuilder {
        crate::types::builders::DurationRangeBuilder::default()
    }
}

/// A builder for [`DurationRange`](crate::types::DurationRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DurationRangeBuilder {
    pub(crate) min_seconds: ::std::option::Option<i32>,
    pub(crate) max_seconds: ::std::option::Option<i32>,
}
impl DurationRangeBuilder {
    /// <p>The minimum value of the duration range. Must be greater than zero.</p>
    pub fn min_seconds(mut self, input: i32) -> Self {
        self.min_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum value of the duration range. Must be greater than zero.</p>
    pub fn set_min_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_seconds = input;
        self
    }
    /// <p>The minimum value of the duration range. Must be greater than zero.</p>
    pub fn get_min_seconds(&self) -> &::std::option::Option<i32> {
        &self.min_seconds
    }
    /// <p>The maximum value of the duration range. Must be less than or equal to 604800 seconds (1 week).</p>
    pub fn max_seconds(mut self, input: i32) -> Self {
        self.max_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum value of the duration range. Must be less than or equal to 604800 seconds (1 week).</p>
    pub fn set_max_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_seconds = input;
        self
    }
    /// <p>The maximum value of the duration range. Must be less than or equal to 604800 seconds (1 week).</p>
    pub fn get_max_seconds(&self) -> &::std::option::Option<i32> {
        &self.max_seconds
    }
    /// Consumes the builder and constructs a [`DurationRange`](crate::types::DurationRange).
    pub fn build(self) -> crate::types::DurationRange {
        crate::types::DurationRange {
            min_seconds: self.min_seconds,
            max_seconds: self.max_seconds,
        }
    }
}
