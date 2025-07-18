// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Time range object with <code>startTime</code> and <code>endTime</code> range in RFC 3339 format. <code>'HH:mm:ss.SSS'</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SupportedHour {
    /// <p>Start Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub start_time: ::std::option::Option<::std::string::String>,
    /// <p>End Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub end_time: ::std::option::Option<::std::string::String>,
}
impl SupportedHour {
    /// <p>Start Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn start_time(&self) -> ::std::option::Option<&str> {
        self.start_time.as_deref()
    }
    /// <p>End Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn end_time(&self) -> ::std::option::Option<&str> {
        self.end_time.as_deref()
    }
}
impl SupportedHour {
    /// Creates a new builder-style object to manufacture [`SupportedHour`](crate::types::SupportedHour).
    pub fn builder() -> crate::types::builders::SupportedHourBuilder {
        crate::types::builders::SupportedHourBuilder::default()
    }
}

/// A builder for [`SupportedHour`](crate::types::SupportedHour).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SupportedHourBuilder {
    pub(crate) start_time: ::std::option::Option<::std::string::String>,
    pub(crate) end_time: ::std::option::Option<::std::string::String>,
}
impl SupportedHourBuilder {
    /// <p>Start Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn start_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Start Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Start Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_time
    }
    /// <p>End Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn end_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.end_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>End Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>End Time. RFC 3339 format <code>'HH:mm:ss.SSS'</code>.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`SupportedHour`](crate::types::SupportedHour).
    pub fn build(self) -> crate::types::SupportedHour {
        crate::types::SupportedHour {
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
}
