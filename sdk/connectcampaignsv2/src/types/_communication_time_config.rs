// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Campaign communication time config
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CommunicationTimeConfig {
    /// Local time zone config
    pub local_time_zone_config: ::std::option::Option<crate::types::LocalTimeZoneConfig>,
    /// Time window config
    pub telephony: ::std::option::Option<crate::types::TimeWindow>,
    /// Time window config
    pub sms: ::std::option::Option<crate::types::TimeWindow>,
    /// Time window config
    pub email: ::std::option::Option<crate::types::TimeWindow>,
}
impl CommunicationTimeConfig {
    /// Local time zone config
    pub fn local_time_zone_config(&self) -> ::std::option::Option<&crate::types::LocalTimeZoneConfig> {
        self.local_time_zone_config.as_ref()
    }
    /// Time window config
    pub fn telephony(&self) -> ::std::option::Option<&crate::types::TimeWindow> {
        self.telephony.as_ref()
    }
    /// Time window config
    pub fn sms(&self) -> ::std::option::Option<&crate::types::TimeWindow> {
        self.sms.as_ref()
    }
    /// Time window config
    pub fn email(&self) -> ::std::option::Option<&crate::types::TimeWindow> {
        self.email.as_ref()
    }
}
impl CommunicationTimeConfig {
    /// Creates a new builder-style object to manufacture [`CommunicationTimeConfig`](crate::types::CommunicationTimeConfig).
    pub fn builder() -> crate::types::builders::CommunicationTimeConfigBuilder {
        crate::types::builders::CommunicationTimeConfigBuilder::default()
    }
}

/// A builder for [`CommunicationTimeConfig`](crate::types::CommunicationTimeConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CommunicationTimeConfigBuilder {
    pub(crate) local_time_zone_config: ::std::option::Option<crate::types::LocalTimeZoneConfig>,
    pub(crate) telephony: ::std::option::Option<crate::types::TimeWindow>,
    pub(crate) sms: ::std::option::Option<crate::types::TimeWindow>,
    pub(crate) email: ::std::option::Option<crate::types::TimeWindow>,
}
impl CommunicationTimeConfigBuilder {
    /// Local time zone config
    /// This field is required.
    pub fn local_time_zone_config(mut self, input: crate::types::LocalTimeZoneConfig) -> Self {
        self.local_time_zone_config = ::std::option::Option::Some(input);
        self
    }
    /// Local time zone config
    pub fn set_local_time_zone_config(mut self, input: ::std::option::Option<crate::types::LocalTimeZoneConfig>) -> Self {
        self.local_time_zone_config = input;
        self
    }
    /// Local time zone config
    pub fn get_local_time_zone_config(&self) -> &::std::option::Option<crate::types::LocalTimeZoneConfig> {
        &self.local_time_zone_config
    }
    /// Time window config
    pub fn telephony(mut self, input: crate::types::TimeWindow) -> Self {
        self.telephony = ::std::option::Option::Some(input);
        self
    }
    /// Time window config
    pub fn set_telephony(mut self, input: ::std::option::Option<crate::types::TimeWindow>) -> Self {
        self.telephony = input;
        self
    }
    /// Time window config
    pub fn get_telephony(&self) -> &::std::option::Option<crate::types::TimeWindow> {
        &self.telephony
    }
    /// Time window config
    pub fn sms(mut self, input: crate::types::TimeWindow) -> Self {
        self.sms = ::std::option::Option::Some(input);
        self
    }
    /// Time window config
    pub fn set_sms(mut self, input: ::std::option::Option<crate::types::TimeWindow>) -> Self {
        self.sms = input;
        self
    }
    /// Time window config
    pub fn get_sms(&self) -> &::std::option::Option<crate::types::TimeWindow> {
        &self.sms
    }
    /// Time window config
    pub fn email(mut self, input: crate::types::TimeWindow) -> Self {
        self.email = ::std::option::Option::Some(input);
        self
    }
    /// Time window config
    pub fn set_email(mut self, input: ::std::option::Option<crate::types::TimeWindow>) -> Self {
        self.email = input;
        self
    }
    /// Time window config
    pub fn get_email(&self) -> &::std::option::Option<crate::types::TimeWindow> {
        &self.email
    }
    /// Consumes the builder and constructs a [`CommunicationTimeConfig`](crate::types::CommunicationTimeConfig).
    pub fn build(self) -> crate::types::CommunicationTimeConfig {
        crate::types::CommunicationTimeConfig {
            local_time_zone_config: self.local_time_zone_config,
            telephony: self.telephony,
            sms: self.sms,
            email: self.email,
        }
    }
}
