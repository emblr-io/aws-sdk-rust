// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>CloudFront Origin Shield.</p>
/// <p>Using Origin Shield can help reduce the load on your origin. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html">Using Origin Shield</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OriginShield {
    /// <p>A flag that specifies whether Origin Shield is enabled.</p>
    /// <p>When it's enabled, CloudFront routes all requests through Origin Shield, which can help protect your origin. When it's disabled, CloudFront might send requests directly to your origin from multiple edge locations or regional edge caches.</p>
    pub enabled: bool,
    /// <p>The Amazon Web Services Region for Origin Shield.</p>
    /// <p>Specify the Amazon Web Services Region that has the lowest latency to your origin. To specify a region, use the region code, not the region name. For example, specify the US East (Ohio) region as <code>us-east-2</code>.</p>
    /// <p>When you enable CloudFront Origin Shield, you must specify the Amazon Web Services Region for Origin Shield. For the list of Amazon Web Services Regions that you can specify, and for help choosing the best Region for your origin, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html#choose-origin-shield-region">Choosing the Amazon Web Services Region for Origin Shield</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
    pub origin_shield_region: ::std::option::Option<::std::string::String>,
}
impl OriginShield {
    /// <p>A flag that specifies whether Origin Shield is enabled.</p>
    /// <p>When it's enabled, CloudFront routes all requests through Origin Shield, which can help protect your origin. When it's disabled, CloudFront might send requests directly to your origin from multiple edge locations or regional edge caches.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// <p>The Amazon Web Services Region for Origin Shield.</p>
    /// <p>Specify the Amazon Web Services Region that has the lowest latency to your origin. To specify a region, use the region code, not the region name. For example, specify the US East (Ohio) region as <code>us-east-2</code>.</p>
    /// <p>When you enable CloudFront Origin Shield, you must specify the Amazon Web Services Region for Origin Shield. For the list of Amazon Web Services Regions that you can specify, and for help choosing the best Region for your origin, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html#choose-origin-shield-region">Choosing the Amazon Web Services Region for Origin Shield</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
    pub fn origin_shield_region(&self) -> ::std::option::Option<&str> {
        self.origin_shield_region.as_deref()
    }
}
impl OriginShield {
    /// Creates a new builder-style object to manufacture [`OriginShield`](crate::types::OriginShield).
    pub fn builder() -> crate::types::builders::OriginShieldBuilder {
        crate::types::builders::OriginShieldBuilder::default()
    }
}

/// A builder for [`OriginShield`](crate::types::OriginShield).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OriginShieldBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) origin_shield_region: ::std::option::Option<::std::string::String>,
}
impl OriginShieldBuilder {
    /// <p>A flag that specifies whether Origin Shield is enabled.</p>
    /// <p>When it's enabled, CloudFront routes all requests through Origin Shield, which can help protect your origin. When it's disabled, CloudFront might send requests directly to your origin from multiple edge locations or regional edge caches.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag that specifies whether Origin Shield is enabled.</p>
    /// <p>When it's enabled, CloudFront routes all requests through Origin Shield, which can help protect your origin. When it's disabled, CloudFront might send requests directly to your origin from multiple edge locations or regional edge caches.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>A flag that specifies whether Origin Shield is enabled.</p>
    /// <p>When it's enabled, CloudFront routes all requests through Origin Shield, which can help protect your origin. When it's disabled, CloudFront might send requests directly to your origin from multiple edge locations or regional edge caches.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The Amazon Web Services Region for Origin Shield.</p>
    /// <p>Specify the Amazon Web Services Region that has the lowest latency to your origin. To specify a region, use the region code, not the region name. For example, specify the US East (Ohio) region as <code>us-east-2</code>.</p>
    /// <p>When you enable CloudFront Origin Shield, you must specify the Amazon Web Services Region for Origin Shield. For the list of Amazon Web Services Regions that you can specify, and for help choosing the best Region for your origin, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html#choose-origin-shield-region">Choosing the Amazon Web Services Region for Origin Shield</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
    pub fn origin_shield_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin_shield_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region for Origin Shield.</p>
    /// <p>Specify the Amazon Web Services Region that has the lowest latency to your origin. To specify a region, use the region code, not the region name. For example, specify the US East (Ohio) region as <code>us-east-2</code>.</p>
    /// <p>When you enable CloudFront Origin Shield, you must specify the Amazon Web Services Region for Origin Shield. For the list of Amazon Web Services Regions that you can specify, and for help choosing the best Region for your origin, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html#choose-origin-shield-region">Choosing the Amazon Web Services Region for Origin Shield</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
    pub fn set_origin_shield_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin_shield_region = input;
        self
    }
    /// <p>The Amazon Web Services Region for Origin Shield.</p>
    /// <p>Specify the Amazon Web Services Region that has the lowest latency to your origin. To specify a region, use the region code, not the region name. For example, specify the US East (Ohio) region as <code>us-east-2</code>.</p>
    /// <p>When you enable CloudFront Origin Shield, you must specify the Amazon Web Services Region for Origin Shield. For the list of Amazon Web Services Regions that you can specify, and for help choosing the best Region for your origin, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-shield.html#choose-origin-shield-region">Choosing the Amazon Web Services Region for Origin Shield</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
    pub fn get_origin_shield_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin_shield_region
    }
    /// Consumes the builder and constructs a [`OriginShield`](crate::types::OriginShield).
    /// This method will fail if any of the following fields are not set:
    /// - [`enabled`](crate::types::builders::OriginShieldBuilder::enabled)
    pub fn build(self) -> ::std::result::Result<crate::types::OriginShield, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OriginShield {
            enabled: self.enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "enabled",
                    "enabled was not specified but it is required when building OriginShield",
                )
            })?,
            origin_shield_region: self.origin_shield_region,
        })
    }
}
