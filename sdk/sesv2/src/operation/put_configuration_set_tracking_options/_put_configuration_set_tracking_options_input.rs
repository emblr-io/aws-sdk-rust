// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to add a custom domain for tracking open and click events to a configuration set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutConfigurationSetTrackingOptionsInput {
    /// <p>The name of the configuration set.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The domain to use to track open and click events.</p>
    pub custom_redirect_domain: ::std::option::Option<::std::string::String>,
    /// <p>The https policy to use for tracking open and click events. If the value is OPTIONAL or HttpsPolicy is not specified, the open trackers use HTTP and click tracker use the original protocol of the link. If the value is REQUIRE, both open and click tracker uses HTTPS and if the value is REQUIRE_OPEN_ONLY open tracker uses HTTPS and link tracker is same as original protocol of the link.</p>
    pub https_policy: ::std::option::Option<crate::types::HttpsPolicy>,
}
impl PutConfigurationSetTrackingOptionsInput {
    /// <p>The name of the configuration set.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// <p>The domain to use to track open and click events.</p>
    pub fn custom_redirect_domain(&self) -> ::std::option::Option<&str> {
        self.custom_redirect_domain.as_deref()
    }
    /// <p>The https policy to use for tracking open and click events. If the value is OPTIONAL or HttpsPolicy is not specified, the open trackers use HTTP and click tracker use the original protocol of the link. If the value is REQUIRE, both open and click tracker uses HTTPS and if the value is REQUIRE_OPEN_ONLY open tracker uses HTTPS and link tracker is same as original protocol of the link.</p>
    pub fn https_policy(&self) -> ::std::option::Option<&crate::types::HttpsPolicy> {
        self.https_policy.as_ref()
    }
}
impl PutConfigurationSetTrackingOptionsInput {
    /// Creates a new builder-style object to manufacture [`PutConfigurationSetTrackingOptionsInput`](crate::operation::put_configuration_set_tracking_options::PutConfigurationSetTrackingOptionsInput).
    pub fn builder() -> crate::operation::put_configuration_set_tracking_options::builders::PutConfigurationSetTrackingOptionsInputBuilder {
        crate::operation::put_configuration_set_tracking_options::builders::PutConfigurationSetTrackingOptionsInputBuilder::default()
    }
}

/// A builder for [`PutConfigurationSetTrackingOptionsInput`](crate::operation::put_configuration_set_tracking_options::PutConfigurationSetTrackingOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutConfigurationSetTrackingOptionsInputBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) custom_redirect_domain: ::std::option::Option<::std::string::String>,
    pub(crate) https_policy: ::std::option::Option<crate::types::HttpsPolicy>,
}
impl PutConfigurationSetTrackingOptionsInputBuilder {
    /// <p>The name of the configuration set.</p>
    /// This field is required.
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration set.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration set.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// <p>The domain to use to track open and click events.</p>
    pub fn custom_redirect_domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_redirect_domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain to use to track open and click events.</p>
    pub fn set_custom_redirect_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_redirect_domain = input;
        self
    }
    /// <p>The domain to use to track open and click events.</p>
    pub fn get_custom_redirect_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_redirect_domain
    }
    /// <p>The https policy to use for tracking open and click events. If the value is OPTIONAL or HttpsPolicy is not specified, the open trackers use HTTP and click tracker use the original protocol of the link. If the value is REQUIRE, both open and click tracker uses HTTPS and if the value is REQUIRE_OPEN_ONLY open tracker uses HTTPS and link tracker is same as original protocol of the link.</p>
    pub fn https_policy(mut self, input: crate::types::HttpsPolicy) -> Self {
        self.https_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The https policy to use for tracking open and click events. If the value is OPTIONAL or HttpsPolicy is not specified, the open trackers use HTTP and click tracker use the original protocol of the link. If the value is REQUIRE, both open and click tracker uses HTTPS and if the value is REQUIRE_OPEN_ONLY open tracker uses HTTPS and link tracker is same as original protocol of the link.</p>
    pub fn set_https_policy(mut self, input: ::std::option::Option<crate::types::HttpsPolicy>) -> Self {
        self.https_policy = input;
        self
    }
    /// <p>The https policy to use for tracking open and click events. If the value is OPTIONAL or HttpsPolicy is not specified, the open trackers use HTTP and click tracker use the original protocol of the link. If the value is REQUIRE, both open and click tracker uses HTTPS and if the value is REQUIRE_OPEN_ONLY open tracker uses HTTPS and link tracker is same as original protocol of the link.</p>
    pub fn get_https_policy(&self) -> &::std::option::Option<crate::types::HttpsPolicy> {
        &self.https_policy
    }
    /// Consumes the builder and constructs a [`PutConfigurationSetTrackingOptionsInput`](crate::operation::put_configuration_set_tracking_options::PutConfigurationSetTrackingOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_configuration_set_tracking_options::PutConfigurationSetTrackingOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_configuration_set_tracking_options::PutConfigurationSetTrackingOptionsInput {
                configuration_set_name: self.configuration_set_name,
                custom_redirect_domain: self.custom_redirect_domain,
                https_policy: self.https_policy,
            },
        )
    }
}
