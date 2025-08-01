// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>To insert an EXT-X-START tag in your HLS playlist, specify a StartTag configuration object with a valid TimeOffset. When you do, you can also optionally specify whether to include a PRECISE value in the EXT-X-START tag.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTag {
    /// <p>Specify the value for TIME-OFFSET within your EXT-X-START tag. Enter a signed floating point value which, if positive, must be less than the configured manifest duration minus three times the configured segment target duration. If negative, the absolute value must be larger than three times the configured segment target duration, and the absolute value must be smaller than the configured manifest duration.</p>
    pub time_offset: f32,
    /// <p>Specify the value for PRECISE within your EXT-X-START tag. Leave blank, or choose false, to use the default value NO. Choose yes to use the value YES.</p>
    pub precise: ::std::option::Option<bool>,
}
impl StartTag {
    /// <p>Specify the value for TIME-OFFSET within your EXT-X-START tag. Enter a signed floating point value which, if positive, must be less than the configured manifest duration minus three times the configured segment target duration. If negative, the absolute value must be larger than three times the configured segment target duration, and the absolute value must be smaller than the configured manifest duration.</p>
    pub fn time_offset(&self) -> f32 {
        self.time_offset
    }
    /// <p>Specify the value for PRECISE within your EXT-X-START tag. Leave blank, or choose false, to use the default value NO. Choose yes to use the value YES.</p>
    pub fn precise(&self) -> ::std::option::Option<bool> {
        self.precise
    }
}
impl StartTag {
    /// Creates a new builder-style object to manufacture [`StartTag`](crate::types::StartTag).
    pub fn builder() -> crate::types::builders::StartTagBuilder {
        crate::types::builders::StartTagBuilder::default()
    }
}

/// A builder for [`StartTag`](crate::types::StartTag).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTagBuilder {
    pub(crate) time_offset: ::std::option::Option<f32>,
    pub(crate) precise: ::std::option::Option<bool>,
}
impl StartTagBuilder {
    /// <p>Specify the value for TIME-OFFSET within your EXT-X-START tag. Enter a signed floating point value which, if positive, must be less than the configured manifest duration minus three times the configured segment target duration. If negative, the absolute value must be larger than three times the configured segment target duration, and the absolute value must be smaller than the configured manifest duration.</p>
    /// This field is required.
    pub fn time_offset(mut self, input: f32) -> Self {
        self.time_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the value for TIME-OFFSET within your EXT-X-START tag. Enter a signed floating point value which, if positive, must be less than the configured manifest duration minus three times the configured segment target duration. If negative, the absolute value must be larger than three times the configured segment target duration, and the absolute value must be smaller than the configured manifest duration.</p>
    pub fn set_time_offset(mut self, input: ::std::option::Option<f32>) -> Self {
        self.time_offset = input;
        self
    }
    /// <p>Specify the value for TIME-OFFSET within your EXT-X-START tag. Enter a signed floating point value which, if positive, must be less than the configured manifest duration minus three times the configured segment target duration. If negative, the absolute value must be larger than three times the configured segment target duration, and the absolute value must be smaller than the configured manifest duration.</p>
    pub fn get_time_offset(&self) -> &::std::option::Option<f32> {
        &self.time_offset
    }
    /// <p>Specify the value for PRECISE within your EXT-X-START tag. Leave blank, or choose false, to use the default value NO. Choose yes to use the value YES.</p>
    pub fn precise(mut self, input: bool) -> Self {
        self.precise = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the value for PRECISE within your EXT-X-START tag. Leave blank, or choose false, to use the default value NO. Choose yes to use the value YES.</p>
    pub fn set_precise(mut self, input: ::std::option::Option<bool>) -> Self {
        self.precise = input;
        self
    }
    /// <p>Specify the value for PRECISE within your EXT-X-START tag. Leave blank, or choose false, to use the default value NO. Choose yes to use the value YES.</p>
    pub fn get_precise(&self) -> &::std::option::Option<bool> {
        &self.precise
    }
    /// Consumes the builder and constructs a [`StartTag`](crate::types::StartTag).
    /// This method will fail if any of the following fields are not set:
    /// - [`time_offset`](crate::types::builders::StartTagBuilder::time_offset)
    pub fn build(self) -> ::std::result::Result<crate::types::StartTag, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StartTag {
            time_offset: self.time_offset.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "time_offset",
                    "time_offset was not specified but it is required when building StartTag",
                )
            })?,
            precise: self.precise,
        })
    }
}
