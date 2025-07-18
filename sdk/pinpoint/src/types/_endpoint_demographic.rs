// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies demographic information about an endpoint, such as the applicable time zone and platform.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EndpointDemographic {
    /// <p>The version of the app that's associated with the endpoint.</p>
    pub app_version: ::std::option::Option<::std::string::String>,
    /// <p>The locale of the endpoint, in the following format: the ISO 639-1 alpha-2 code, followed by an underscore (_), followed by an ISO 3166-1 alpha-2 value.</p>
    pub locale: ::std::option::Option<::std::string::String>,
    /// <p>The manufacturer of the endpoint device, such as apple or samsung.</p>
    pub make: ::std::option::Option<::std::string::String>,
    /// <p>The model name or number of the endpoint device, such as iPhone or SM-G900F.</p>
    pub model: ::std::option::Option<::std::string::String>,
    /// <p>The model version of the endpoint device.</p>
    pub model_version: ::std::option::Option<::std::string::String>,
    /// <p>The platform of the endpoint device, such as ios.</p>
    pub platform: ::std::option::Option<::std::string::String>,
    /// <p>The platform version of the endpoint device.</p>
    pub platform_version: ::std::option::Option<::std::string::String>,
    /// <p>The time zone of the endpoint, specified as a tz database name value, such as America/Los_Angeles.</p>
    pub timezone: ::std::option::Option<::std::string::String>,
}
impl EndpointDemographic {
    /// <p>The version of the app that's associated with the endpoint.</p>
    pub fn app_version(&self) -> ::std::option::Option<&str> {
        self.app_version.as_deref()
    }
    /// <p>The locale of the endpoint, in the following format: the ISO 639-1 alpha-2 code, followed by an underscore (_), followed by an ISO 3166-1 alpha-2 value.</p>
    pub fn locale(&self) -> ::std::option::Option<&str> {
        self.locale.as_deref()
    }
    /// <p>The manufacturer of the endpoint device, such as apple or samsung.</p>
    pub fn make(&self) -> ::std::option::Option<&str> {
        self.make.as_deref()
    }
    /// <p>The model name or number of the endpoint device, such as iPhone or SM-G900F.</p>
    pub fn model(&self) -> ::std::option::Option<&str> {
        self.model.as_deref()
    }
    /// <p>The model version of the endpoint device.</p>
    pub fn model_version(&self) -> ::std::option::Option<&str> {
        self.model_version.as_deref()
    }
    /// <p>The platform of the endpoint device, such as ios.</p>
    pub fn platform(&self) -> ::std::option::Option<&str> {
        self.platform.as_deref()
    }
    /// <p>The platform version of the endpoint device.</p>
    pub fn platform_version(&self) -> ::std::option::Option<&str> {
        self.platform_version.as_deref()
    }
    /// <p>The time zone of the endpoint, specified as a tz database name value, such as America/Los_Angeles.</p>
    pub fn timezone(&self) -> ::std::option::Option<&str> {
        self.timezone.as_deref()
    }
}
impl EndpointDemographic {
    /// Creates a new builder-style object to manufacture [`EndpointDemographic`](crate::types::EndpointDemographic).
    pub fn builder() -> crate::types::builders::EndpointDemographicBuilder {
        crate::types::builders::EndpointDemographicBuilder::default()
    }
}

/// A builder for [`EndpointDemographic`](crate::types::EndpointDemographic).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointDemographicBuilder {
    pub(crate) app_version: ::std::option::Option<::std::string::String>,
    pub(crate) locale: ::std::option::Option<::std::string::String>,
    pub(crate) make: ::std::option::Option<::std::string::String>,
    pub(crate) model: ::std::option::Option<::std::string::String>,
    pub(crate) model_version: ::std::option::Option<::std::string::String>,
    pub(crate) platform: ::std::option::Option<::std::string::String>,
    pub(crate) platform_version: ::std::option::Option<::std::string::String>,
    pub(crate) timezone: ::std::option::Option<::std::string::String>,
}
impl EndpointDemographicBuilder {
    /// <p>The version of the app that's associated with the endpoint.</p>
    pub fn app_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the app that's associated with the endpoint.</p>
    pub fn set_app_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_version = input;
        self
    }
    /// <p>The version of the app that's associated with the endpoint.</p>
    pub fn get_app_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_version
    }
    /// <p>The locale of the endpoint, in the following format: the ISO 639-1 alpha-2 code, followed by an underscore (_), followed by an ISO 3166-1 alpha-2 value.</p>
    pub fn locale(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.locale = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The locale of the endpoint, in the following format: the ISO 639-1 alpha-2 code, followed by an underscore (_), followed by an ISO 3166-1 alpha-2 value.</p>
    pub fn set_locale(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.locale = input;
        self
    }
    /// <p>The locale of the endpoint, in the following format: the ISO 639-1 alpha-2 code, followed by an underscore (_), followed by an ISO 3166-1 alpha-2 value.</p>
    pub fn get_locale(&self) -> &::std::option::Option<::std::string::String> {
        &self.locale
    }
    /// <p>The manufacturer of the endpoint device, such as apple or samsung.</p>
    pub fn make(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.make = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The manufacturer of the endpoint device, such as apple or samsung.</p>
    pub fn set_make(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.make = input;
        self
    }
    /// <p>The manufacturer of the endpoint device, such as apple or samsung.</p>
    pub fn get_make(&self) -> &::std::option::Option<::std::string::String> {
        &self.make
    }
    /// <p>The model name or number of the endpoint device, such as iPhone or SM-G900F.</p>
    pub fn model(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The model name or number of the endpoint device, such as iPhone or SM-G900F.</p>
    pub fn set_model(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model = input;
        self
    }
    /// <p>The model name or number of the endpoint device, such as iPhone or SM-G900F.</p>
    pub fn get_model(&self) -> &::std::option::Option<::std::string::String> {
        &self.model
    }
    /// <p>The model version of the endpoint device.</p>
    pub fn model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The model version of the endpoint device.</p>
    pub fn set_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_version = input;
        self
    }
    /// <p>The model version of the endpoint device.</p>
    pub fn get_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_version
    }
    /// <p>The platform of the endpoint device, such as ios.</p>
    pub fn platform(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The platform of the endpoint device, such as ios.</p>
    pub fn set_platform(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform = input;
        self
    }
    /// <p>The platform of the endpoint device, such as ios.</p>
    pub fn get_platform(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform
    }
    /// <p>The platform version of the endpoint device.</p>
    pub fn platform_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The platform version of the endpoint device.</p>
    pub fn set_platform_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform_version = input;
        self
    }
    /// <p>The platform version of the endpoint device.</p>
    pub fn get_platform_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform_version
    }
    /// <p>The time zone of the endpoint, specified as a tz database name value, such as America/Los_Angeles.</p>
    pub fn timezone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timezone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time zone of the endpoint, specified as a tz database name value, such as America/Los_Angeles.</p>
    pub fn set_timezone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timezone = input;
        self
    }
    /// <p>The time zone of the endpoint, specified as a tz database name value, such as America/Los_Angeles.</p>
    pub fn get_timezone(&self) -> &::std::option::Option<::std::string::String> {
        &self.timezone
    }
    /// Consumes the builder and constructs a [`EndpointDemographic`](crate::types::EndpointDemographic).
    pub fn build(self) -> crate::types::EndpointDemographic {
        crate::types::EndpointDemographic {
            app_version: self.app_version,
            locale: self.locale,
            make: self.make,
            model: self.model,
            model_version: self.model_version,
            platform: self.platform,
            platform_version: self.platform_version,
            timezone: self.timezone,
        }
    }
}
