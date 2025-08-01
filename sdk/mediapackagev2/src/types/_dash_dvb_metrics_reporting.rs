// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>For use with DVB-DASH profiles only. The settings for error reporting from the playback device that you want Elemental MediaPackage to pass through to the manifest.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DashDvbMetricsReporting {
    /// <p>The URL where playback devices send error reports.</p>
    pub reporting_url: ::std::string::String,
    /// <p>The number of playback devices per 1000 that will send error reports to the reporting URL. This represents the probability that a playback device will be a reporting player for this session.</p>
    pub probability: ::std::option::Option<i32>,
}
impl DashDvbMetricsReporting {
    /// <p>The URL where playback devices send error reports.</p>
    pub fn reporting_url(&self) -> &str {
        use std::ops::Deref;
        self.reporting_url.deref()
    }
    /// <p>The number of playback devices per 1000 that will send error reports to the reporting URL. This represents the probability that a playback device will be a reporting player for this session.</p>
    pub fn probability(&self) -> ::std::option::Option<i32> {
        self.probability
    }
}
impl DashDvbMetricsReporting {
    /// Creates a new builder-style object to manufacture [`DashDvbMetricsReporting`](crate::types::DashDvbMetricsReporting).
    pub fn builder() -> crate::types::builders::DashDvbMetricsReportingBuilder {
        crate::types::builders::DashDvbMetricsReportingBuilder::default()
    }
}

/// A builder for [`DashDvbMetricsReporting`](crate::types::DashDvbMetricsReporting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DashDvbMetricsReportingBuilder {
    pub(crate) reporting_url: ::std::option::Option<::std::string::String>,
    pub(crate) probability: ::std::option::Option<i32>,
}
impl DashDvbMetricsReportingBuilder {
    /// <p>The URL where playback devices send error reports.</p>
    /// This field is required.
    pub fn reporting_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reporting_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL where playback devices send error reports.</p>
    pub fn set_reporting_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reporting_url = input;
        self
    }
    /// <p>The URL where playback devices send error reports.</p>
    pub fn get_reporting_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.reporting_url
    }
    /// <p>The number of playback devices per 1000 that will send error reports to the reporting URL. This represents the probability that a playback device will be a reporting player for this session.</p>
    pub fn probability(mut self, input: i32) -> Self {
        self.probability = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of playback devices per 1000 that will send error reports to the reporting URL. This represents the probability that a playback device will be a reporting player for this session.</p>
    pub fn set_probability(mut self, input: ::std::option::Option<i32>) -> Self {
        self.probability = input;
        self
    }
    /// <p>The number of playback devices per 1000 that will send error reports to the reporting URL. This represents the probability that a playback device will be a reporting player for this session.</p>
    pub fn get_probability(&self) -> &::std::option::Option<i32> {
        &self.probability
    }
    /// Consumes the builder and constructs a [`DashDvbMetricsReporting`](crate::types::DashDvbMetricsReporting).
    /// This method will fail if any of the following fields are not set:
    /// - [`reporting_url`](crate::types::builders::DashDvbMetricsReportingBuilder::reporting_url)
    pub fn build(self) -> ::std::result::Result<crate::types::DashDvbMetricsReporting, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DashDvbMetricsReporting {
            reporting_url: self.reporting_url.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reporting_url",
                    "reporting_url was not specified but it is required when building DashDvbMetricsReporting",
                )
            })?,
            probability: self.probability,
        })
    }
}
