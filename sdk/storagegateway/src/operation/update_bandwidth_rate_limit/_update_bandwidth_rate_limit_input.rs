// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON object containing one or more of the following fields:</p>
/// <ul>
/// <li>
/// <p><code>UpdateBandwidthRateLimitInput$AverageDownloadRateLimitInBitsPerSec</code></p></li>
/// <li>
/// <p><code>UpdateBandwidthRateLimitInput$AverageUploadRateLimitInBitsPerSec</code></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateBandwidthRateLimitInput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub gateway_arn: ::std::option::Option<::std::string::String>,
    /// <p>The average upload bandwidth rate limit in bits per second.</p>
    pub average_upload_rate_limit_in_bits_per_sec: ::std::option::Option<i64>,
    /// <p>The average download bandwidth rate limit in bits per second.</p>
    pub average_download_rate_limit_in_bits_per_sec: ::std::option::Option<i64>,
}
impl UpdateBandwidthRateLimitInput {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn gateway_arn(&self) -> ::std::option::Option<&str> {
        self.gateway_arn.as_deref()
    }
    /// <p>The average upload bandwidth rate limit in bits per second.</p>
    pub fn average_upload_rate_limit_in_bits_per_sec(&self) -> ::std::option::Option<i64> {
        self.average_upload_rate_limit_in_bits_per_sec
    }
    /// <p>The average download bandwidth rate limit in bits per second.</p>
    pub fn average_download_rate_limit_in_bits_per_sec(&self) -> ::std::option::Option<i64> {
        self.average_download_rate_limit_in_bits_per_sec
    }
}
impl UpdateBandwidthRateLimitInput {
    /// Creates a new builder-style object to manufacture [`UpdateBandwidthRateLimitInput`](crate::operation::update_bandwidth_rate_limit::UpdateBandwidthRateLimitInput).
    pub fn builder() -> crate::operation::update_bandwidth_rate_limit::builders::UpdateBandwidthRateLimitInputBuilder {
        crate::operation::update_bandwidth_rate_limit::builders::UpdateBandwidthRateLimitInputBuilder::default()
    }
}

/// A builder for [`UpdateBandwidthRateLimitInput`](crate::operation::update_bandwidth_rate_limit::UpdateBandwidthRateLimitInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateBandwidthRateLimitInputBuilder {
    pub(crate) gateway_arn: ::std::option::Option<::std::string::String>,
    pub(crate) average_upload_rate_limit_in_bits_per_sec: ::std::option::Option<i64>,
    pub(crate) average_download_rate_limit_in_bits_per_sec: ::std::option::Option<i64>,
}
impl UpdateBandwidthRateLimitInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    /// This field is required.
    pub fn gateway_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.gateway_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn set_gateway_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.gateway_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the gateway. Use the <code>ListGateways</code> operation to return a list of gateways for your account and Amazon Web Services Region.</p>
    pub fn get_gateway_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.gateway_arn
    }
    /// <p>The average upload bandwidth rate limit in bits per second.</p>
    pub fn average_upload_rate_limit_in_bits_per_sec(mut self, input: i64) -> Self {
        self.average_upload_rate_limit_in_bits_per_sec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The average upload bandwidth rate limit in bits per second.</p>
    pub fn set_average_upload_rate_limit_in_bits_per_sec(mut self, input: ::std::option::Option<i64>) -> Self {
        self.average_upload_rate_limit_in_bits_per_sec = input;
        self
    }
    /// <p>The average upload bandwidth rate limit in bits per second.</p>
    pub fn get_average_upload_rate_limit_in_bits_per_sec(&self) -> &::std::option::Option<i64> {
        &self.average_upload_rate_limit_in_bits_per_sec
    }
    /// <p>The average download bandwidth rate limit in bits per second.</p>
    pub fn average_download_rate_limit_in_bits_per_sec(mut self, input: i64) -> Self {
        self.average_download_rate_limit_in_bits_per_sec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The average download bandwidth rate limit in bits per second.</p>
    pub fn set_average_download_rate_limit_in_bits_per_sec(mut self, input: ::std::option::Option<i64>) -> Self {
        self.average_download_rate_limit_in_bits_per_sec = input;
        self
    }
    /// <p>The average download bandwidth rate limit in bits per second.</p>
    pub fn get_average_download_rate_limit_in_bits_per_sec(&self) -> &::std::option::Option<i64> {
        &self.average_download_rate_limit_in_bits_per_sec
    }
    /// Consumes the builder and constructs a [`UpdateBandwidthRateLimitInput`](crate::operation::update_bandwidth_rate_limit::UpdateBandwidthRateLimitInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_bandwidth_rate_limit::UpdateBandwidthRateLimitInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_bandwidth_rate_limit::UpdateBandwidthRateLimitInput {
            gateway_arn: self.gateway_arn,
            average_upload_rate_limit_in_bits_per_sec: self.average_upload_rate_limit_in_bits_per_sec,
            average_download_rate_limit_in_bits_per_sec: self.average_download_rate_limit_in_bits_per_sec,
        })
    }
}
