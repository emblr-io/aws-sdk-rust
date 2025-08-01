// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>For a campaign, specifies limits on the messages that the campaign can send. For an application, specifies the default limits for messages that campaigns in the application can send.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CampaignLimits {
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during a 24-hour period. For an application, this value specifies the default limit for the number of messages that campaigns and journeys can send to a single endpoint during a 24-hour period. The maximum value is 100.</p>
    pub daily: ::std::option::Option<i32>,
    /// <p>The maximum amount of time, in seconds, that a campaign can attempt to deliver a message after the scheduled start time for the campaign. The minimum value is 60 seconds.</p>
    pub maximum_duration: ::std::option::Option<i32>,
    /// <p>The maximum number of messages that a campaign can send each second. For an application, this value specifies the default limit for the number of messages that campaigns can send each second. The minimum value is 1. The maximum value is 20,000.</p>
    pub messages_per_second: ::std::option::Option<i32>,
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during the course of the campaign. If a campaign recurs, this setting applies to all runs of the campaign. The maximum value is 100.</p>
    pub total: ::std::option::Option<i32>,
    /// <p>The maximum total number of messages that the campaign can send per user session.</p>
    pub session: ::std::option::Option<i32>,
}
impl CampaignLimits {
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during a 24-hour period. For an application, this value specifies the default limit for the number of messages that campaigns and journeys can send to a single endpoint during a 24-hour period. The maximum value is 100.</p>
    pub fn daily(&self) -> ::std::option::Option<i32> {
        self.daily
    }
    /// <p>The maximum amount of time, in seconds, that a campaign can attempt to deliver a message after the scheduled start time for the campaign. The minimum value is 60 seconds.</p>
    pub fn maximum_duration(&self) -> ::std::option::Option<i32> {
        self.maximum_duration
    }
    /// <p>The maximum number of messages that a campaign can send each second. For an application, this value specifies the default limit for the number of messages that campaigns can send each second. The minimum value is 1. The maximum value is 20,000.</p>
    pub fn messages_per_second(&self) -> ::std::option::Option<i32> {
        self.messages_per_second
    }
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during the course of the campaign. If a campaign recurs, this setting applies to all runs of the campaign. The maximum value is 100.</p>
    pub fn total(&self) -> ::std::option::Option<i32> {
        self.total
    }
    /// <p>The maximum total number of messages that the campaign can send per user session.</p>
    pub fn session(&self) -> ::std::option::Option<i32> {
        self.session
    }
}
impl CampaignLimits {
    /// Creates a new builder-style object to manufacture [`CampaignLimits`](crate::types::CampaignLimits).
    pub fn builder() -> crate::types::builders::CampaignLimitsBuilder {
        crate::types::builders::CampaignLimitsBuilder::default()
    }
}

/// A builder for [`CampaignLimits`](crate::types::CampaignLimits).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CampaignLimitsBuilder {
    pub(crate) daily: ::std::option::Option<i32>,
    pub(crate) maximum_duration: ::std::option::Option<i32>,
    pub(crate) messages_per_second: ::std::option::Option<i32>,
    pub(crate) total: ::std::option::Option<i32>,
    pub(crate) session: ::std::option::Option<i32>,
}
impl CampaignLimitsBuilder {
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during a 24-hour period. For an application, this value specifies the default limit for the number of messages that campaigns and journeys can send to a single endpoint during a 24-hour period. The maximum value is 100.</p>
    pub fn daily(mut self, input: i32) -> Self {
        self.daily = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during a 24-hour period. For an application, this value specifies the default limit for the number of messages that campaigns and journeys can send to a single endpoint during a 24-hour period. The maximum value is 100.</p>
    pub fn set_daily(mut self, input: ::std::option::Option<i32>) -> Self {
        self.daily = input;
        self
    }
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during a 24-hour period. For an application, this value specifies the default limit for the number of messages that campaigns and journeys can send to a single endpoint during a 24-hour period. The maximum value is 100.</p>
    pub fn get_daily(&self) -> &::std::option::Option<i32> {
        &self.daily
    }
    /// <p>The maximum amount of time, in seconds, that a campaign can attempt to deliver a message after the scheduled start time for the campaign. The minimum value is 60 seconds.</p>
    pub fn maximum_duration(mut self, input: i32) -> Self {
        self.maximum_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum amount of time, in seconds, that a campaign can attempt to deliver a message after the scheduled start time for the campaign. The minimum value is 60 seconds.</p>
    pub fn set_maximum_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_duration = input;
        self
    }
    /// <p>The maximum amount of time, in seconds, that a campaign can attempt to deliver a message after the scheduled start time for the campaign. The minimum value is 60 seconds.</p>
    pub fn get_maximum_duration(&self) -> &::std::option::Option<i32> {
        &self.maximum_duration
    }
    /// <p>The maximum number of messages that a campaign can send each second. For an application, this value specifies the default limit for the number of messages that campaigns can send each second. The minimum value is 1. The maximum value is 20,000.</p>
    pub fn messages_per_second(mut self, input: i32) -> Self {
        self.messages_per_second = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of messages that a campaign can send each second. For an application, this value specifies the default limit for the number of messages that campaigns can send each second. The minimum value is 1. The maximum value is 20,000.</p>
    pub fn set_messages_per_second(mut self, input: ::std::option::Option<i32>) -> Self {
        self.messages_per_second = input;
        self
    }
    /// <p>The maximum number of messages that a campaign can send each second. For an application, this value specifies the default limit for the number of messages that campaigns can send each second. The minimum value is 1. The maximum value is 20,000.</p>
    pub fn get_messages_per_second(&self) -> &::std::option::Option<i32> {
        &self.messages_per_second
    }
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during the course of the campaign. If a campaign recurs, this setting applies to all runs of the campaign. The maximum value is 100.</p>
    pub fn total(mut self, input: i32) -> Self {
        self.total = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during the course of the campaign. If a campaign recurs, this setting applies to all runs of the campaign. The maximum value is 100.</p>
    pub fn set_total(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total = input;
        self
    }
    /// <p>The maximum number of messages that a campaign can send to a single endpoint during the course of the campaign. If a campaign recurs, this setting applies to all runs of the campaign. The maximum value is 100.</p>
    pub fn get_total(&self) -> &::std::option::Option<i32> {
        &self.total
    }
    /// <p>The maximum total number of messages that the campaign can send per user session.</p>
    pub fn session(mut self, input: i32) -> Self {
        self.session = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum total number of messages that the campaign can send per user session.</p>
    pub fn set_session(mut self, input: ::std::option::Option<i32>) -> Self {
        self.session = input;
        self
    }
    /// <p>The maximum total number of messages that the campaign can send per user session.</p>
    pub fn get_session(&self) -> &::std::option::Option<i32> {
        &self.session
    }
    /// Consumes the builder and constructs a [`CampaignLimits`](crate::types::CampaignLimits).
    pub fn build(self) -> crate::types::CampaignLimits {
        crate::types::CampaignLimits {
            daily: self.daily,
            maximum_duration: self.maximum_duration,
            messages_per_second: self.messages_per_second,
            total: self.total,
            session: self.session,
        }
    }
}
