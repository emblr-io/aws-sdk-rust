// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The start time or end time for an hours of operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HoursOfOperationTimeSlice {
    /// <p>The hours.</p>
    pub hours: i32,
    /// <p>The minutes.</p>
    pub minutes: i32,
}
impl HoursOfOperationTimeSlice {
    /// <p>The hours.</p>
    pub fn hours(&self) -> i32 {
        self.hours
    }
    /// <p>The minutes.</p>
    pub fn minutes(&self) -> i32 {
        self.minutes
    }
}
impl HoursOfOperationTimeSlice {
    /// Creates a new builder-style object to manufacture [`HoursOfOperationTimeSlice`](crate::types::HoursOfOperationTimeSlice).
    pub fn builder() -> crate::types::builders::HoursOfOperationTimeSliceBuilder {
        crate::types::builders::HoursOfOperationTimeSliceBuilder::default()
    }
}

/// A builder for [`HoursOfOperationTimeSlice`](crate::types::HoursOfOperationTimeSlice).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HoursOfOperationTimeSliceBuilder {
    pub(crate) hours: ::std::option::Option<i32>,
    pub(crate) minutes: ::std::option::Option<i32>,
}
impl HoursOfOperationTimeSliceBuilder {
    /// <p>The hours.</p>
    /// This field is required.
    pub fn hours(mut self, input: i32) -> Self {
        self.hours = ::std::option::Option::Some(input);
        self
    }
    /// <p>The hours.</p>
    pub fn set_hours(mut self, input: ::std::option::Option<i32>) -> Self {
        self.hours = input;
        self
    }
    /// <p>The hours.</p>
    pub fn get_hours(&self) -> &::std::option::Option<i32> {
        &self.hours
    }
    /// <p>The minutes.</p>
    /// This field is required.
    pub fn minutes(mut self, input: i32) -> Self {
        self.minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minutes.</p>
    pub fn set_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minutes = input;
        self
    }
    /// <p>The minutes.</p>
    pub fn get_minutes(&self) -> &::std::option::Option<i32> {
        &self.minutes
    }
    /// Consumes the builder and constructs a [`HoursOfOperationTimeSlice`](crate::types::HoursOfOperationTimeSlice).
    /// This method will fail if any of the following fields are not set:
    /// - [`hours`](crate::types::builders::HoursOfOperationTimeSliceBuilder::hours)
    /// - [`minutes`](crate::types::builders::HoursOfOperationTimeSliceBuilder::minutes)
    pub fn build(self) -> ::std::result::Result<crate::types::HoursOfOperationTimeSlice, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::HoursOfOperationTimeSlice {
            hours: self.hours.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "hours",
                    "hours was not specified but it is required when building HoursOfOperationTimeSlice",
                )
            })?,
            minutes: self.minutes.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "minutes",
                    "minutes was not specified but it is required when building HoursOfOperationTimeSlice",
                )
            })?,
        })
    }
}
