// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a time zone. Includes the name of the time zone and the offset from UTC in seconds.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimeZone {
    /// <p>The name of the time zone, following the <a href="https://www.iana.org/time-zones"> IANA time zone standard</a>. For example, <code>America/Los_Angeles</code>.</p>
    pub name: ::std::string::String,
    /// <p>The time zone's offset, in seconds, from UTC.</p>
    pub offset: ::std::option::Option<i32>,
}
impl TimeZone {
    /// <p>The name of the time zone, following the <a href="https://www.iana.org/time-zones"> IANA time zone standard</a>. For example, <code>America/Los_Angeles</code>.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The time zone's offset, in seconds, from UTC.</p>
    pub fn offset(&self) -> ::std::option::Option<i32> {
        self.offset
    }
}
impl TimeZone {
    /// Creates a new builder-style object to manufacture [`TimeZone`](crate::types::TimeZone).
    pub fn builder() -> crate::types::builders::TimeZoneBuilder {
        crate::types::builders::TimeZoneBuilder::default()
    }
}

/// A builder for [`TimeZone`](crate::types::TimeZone).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimeZoneBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) offset: ::std::option::Option<i32>,
}
impl TimeZoneBuilder {
    /// <p>The name of the time zone, following the <a href="https://www.iana.org/time-zones"> IANA time zone standard</a>. For example, <code>America/Los_Angeles</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the time zone, following the <a href="https://www.iana.org/time-zones"> IANA time zone standard</a>. For example, <code>America/Los_Angeles</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the time zone, following the <a href="https://www.iana.org/time-zones"> IANA time zone standard</a>. For example, <code>America/Los_Angeles</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time zone's offset, in seconds, from UTC.</p>
    pub fn offset(mut self, input: i32) -> Self {
        self.offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time zone's offset, in seconds, from UTC.</p>
    pub fn set_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.offset = input;
        self
    }
    /// <p>The time zone's offset, in seconds, from UTC.</p>
    pub fn get_offset(&self) -> &::std::option::Option<i32> {
        &self.offset
    }
    /// Consumes the builder and constructs a [`TimeZone`](crate::types::TimeZone).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::TimeZoneBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::TimeZone, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TimeZone {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building TimeZone",
                )
            })?,
            offset: self.offset,
        })
    }
}
