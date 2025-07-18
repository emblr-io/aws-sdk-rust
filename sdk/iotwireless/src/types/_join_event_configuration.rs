// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Join event configuration object for enabling or disabling topic.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JoinEventConfiguration {
    /// <p>Join event configuration object for enabling or disabling LoRaWAN related event topics.</p>
    pub lo_ra_wan: ::std::option::Option<crate::types::LoRaWanJoinEventNotificationConfigurations>,
    /// <p>Denotes whether the wireless device ID join event topic is enabled or disabled.</p>
    pub wireless_device_id_event_topic: ::std::option::Option<crate::types::EventNotificationTopicStatus>,
}
impl JoinEventConfiguration {
    /// <p>Join event configuration object for enabling or disabling LoRaWAN related event topics.</p>
    pub fn lo_ra_wan(&self) -> ::std::option::Option<&crate::types::LoRaWanJoinEventNotificationConfigurations> {
        self.lo_ra_wan.as_ref()
    }
    /// <p>Denotes whether the wireless device ID join event topic is enabled or disabled.</p>
    pub fn wireless_device_id_event_topic(&self) -> ::std::option::Option<&crate::types::EventNotificationTopicStatus> {
        self.wireless_device_id_event_topic.as_ref()
    }
}
impl JoinEventConfiguration {
    /// Creates a new builder-style object to manufacture [`JoinEventConfiguration`](crate::types::JoinEventConfiguration).
    pub fn builder() -> crate::types::builders::JoinEventConfigurationBuilder {
        crate::types::builders::JoinEventConfigurationBuilder::default()
    }
}

/// A builder for [`JoinEventConfiguration`](crate::types::JoinEventConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JoinEventConfigurationBuilder {
    pub(crate) lo_ra_wan: ::std::option::Option<crate::types::LoRaWanJoinEventNotificationConfigurations>,
    pub(crate) wireless_device_id_event_topic: ::std::option::Option<crate::types::EventNotificationTopicStatus>,
}
impl JoinEventConfigurationBuilder {
    /// <p>Join event configuration object for enabling or disabling LoRaWAN related event topics.</p>
    pub fn lo_ra_wan(mut self, input: crate::types::LoRaWanJoinEventNotificationConfigurations) -> Self {
        self.lo_ra_wan = ::std::option::Option::Some(input);
        self
    }
    /// <p>Join event configuration object for enabling or disabling LoRaWAN related event topics.</p>
    pub fn set_lo_ra_wan(mut self, input: ::std::option::Option<crate::types::LoRaWanJoinEventNotificationConfigurations>) -> Self {
        self.lo_ra_wan = input;
        self
    }
    /// <p>Join event configuration object for enabling or disabling LoRaWAN related event topics.</p>
    pub fn get_lo_ra_wan(&self) -> &::std::option::Option<crate::types::LoRaWanJoinEventNotificationConfigurations> {
        &self.lo_ra_wan
    }
    /// <p>Denotes whether the wireless device ID join event topic is enabled or disabled.</p>
    pub fn wireless_device_id_event_topic(mut self, input: crate::types::EventNotificationTopicStatus) -> Self {
        self.wireless_device_id_event_topic = ::std::option::Option::Some(input);
        self
    }
    /// <p>Denotes whether the wireless device ID join event topic is enabled or disabled.</p>
    pub fn set_wireless_device_id_event_topic(mut self, input: ::std::option::Option<crate::types::EventNotificationTopicStatus>) -> Self {
        self.wireless_device_id_event_topic = input;
        self
    }
    /// <p>Denotes whether the wireless device ID join event topic is enabled or disabled.</p>
    pub fn get_wireless_device_id_event_topic(&self) -> &::std::option::Option<crate::types::EventNotificationTopicStatus> {
        &self.wireless_device_id_event_topic
    }
    /// Consumes the builder and constructs a [`JoinEventConfiguration`](crate::types::JoinEventConfiguration).
    pub fn build(self) -> crate::types::JoinEventConfiguration {
        crate::types::JoinEventConfiguration {
            lo_ra_wan: self.lo_ra_wan,
            wireless_device_id_event_topic: self.wireless_device_id_event_topic,
        }
    }
}
