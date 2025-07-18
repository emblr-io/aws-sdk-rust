// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A date range for the date filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DateRange {
    /// <p>A date range value for the date filter.</p>
    pub value: ::std::option::Option<i32>,
    /// <p>A date range unit for the date filter.</p>
    pub unit: ::std::option::Option<crate::types::DateRangeUnit>,
}
impl DateRange {
    /// <p>A date range value for the date filter.</p>
    pub fn value(&self) -> ::std::option::Option<i32> {
        self.value
    }
    /// <p>A date range unit for the date filter.</p>
    pub fn unit(&self) -> ::std::option::Option<&crate::types::DateRangeUnit> {
        self.unit.as_ref()
    }
}
impl DateRange {
    /// Creates a new builder-style object to manufacture [`DateRange`](crate::types::DateRange).
    pub fn builder() -> crate::types::builders::DateRangeBuilder {
        crate::types::builders::DateRangeBuilder::default()
    }
}

/// A builder for [`DateRange`](crate::types::DateRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DateRangeBuilder {
    pub(crate) value: ::std::option::Option<i32>,
    pub(crate) unit: ::std::option::Option<crate::types::DateRangeUnit>,
}
impl DateRangeBuilder {
    /// <p>A date range value for the date filter.</p>
    pub fn value(mut self, input: i32) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>A date range value for the date filter.</p>
    pub fn set_value(mut self, input: ::std::option::Option<i32>) -> Self {
        self.value = input;
        self
    }
    /// <p>A date range value for the date filter.</p>
    pub fn get_value(&self) -> &::std::option::Option<i32> {
        &self.value
    }
    /// <p>A date range unit for the date filter.</p>
    pub fn unit(mut self, input: crate::types::DateRangeUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>A date range unit for the date filter.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::DateRangeUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>A date range unit for the date filter.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::DateRangeUnit> {
        &self.unit
    }
    /// Consumes the builder and constructs a [`DateRange`](crate::types::DateRange).
    pub fn build(self) -> crate::types::DateRange {
        crate::types::DateRange {
            value: self.value,
            unit: self.unit,
        }
    }
}
