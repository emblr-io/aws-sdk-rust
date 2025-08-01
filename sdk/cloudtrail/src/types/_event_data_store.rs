// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A storage lake of event data against which you can run complex SQL-based queries. An event data store can include events that you have logged on your account. To select events for an event data store, use <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-concepts.html#adv-event-selectors">advanced event selectors</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EventDataStore {
    /// <p>The ARN of the event data store.</p>
    pub event_data_store_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the event data store.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the event data store is protected from termination.</p>
    #[deprecated(note = "TerminationProtectionEnabled is no longer returned by ListEventDataStores")]
    pub termination_protection_enabled: ::std::option::Option<bool>,
    /// <p>The status of an event data store.</p>
    #[deprecated(note = "Status is no longer returned by ListEventDataStores")]
    pub status: ::std::option::Option<crate::types::EventDataStoreStatus>,
    /// <p>The advanced event selectors that were used to select events for the data store.</p>
    #[deprecated(note = "AdvancedEventSelectors is no longer returned by ListEventDataStores")]
    pub advanced_event_selectors: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>,
    /// <p>Indicates whether the event data store includes events from all Regions, or only from the Region in which it was created.</p>
    #[deprecated(note = "MultiRegionEnabled is no longer returned by ListEventDataStores")]
    pub multi_region_enabled: ::std::option::Option<bool>,
    /// <p>Indicates that an event data store is collecting logged events for an organization.</p>
    #[deprecated(note = "OrganizationEnabled is no longer returned by ListEventDataStores")]
    pub organization_enabled: ::std::option::Option<bool>,
    /// <p>The retention period, in days.</p>
    #[deprecated(note = "RetentionPeriod is no longer returned by ListEventDataStores")]
    pub retention_period: ::std::option::Option<i32>,
    /// <p>The timestamp of the event data store's creation.</p>
    #[deprecated(note = "CreatedTimestamp is no longer returned by ListEventDataStores")]
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp showing when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    #[deprecated(note = "UpdatedTimestamp is no longer returned by ListEventDataStores")]
    pub updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl EventDataStore {
    /// <p>The ARN of the event data store.</p>
    pub fn event_data_store_arn(&self) -> ::std::option::Option<&str> {
        self.event_data_store_arn.as_deref()
    }
    /// <p>The name of the event data store.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Indicates whether the event data store is protected from termination.</p>
    #[deprecated(note = "TerminationProtectionEnabled is no longer returned by ListEventDataStores")]
    pub fn termination_protection_enabled(&self) -> ::std::option::Option<bool> {
        self.termination_protection_enabled
    }
    /// <p>The status of an event data store.</p>
    #[deprecated(note = "Status is no longer returned by ListEventDataStores")]
    pub fn status(&self) -> ::std::option::Option<&crate::types::EventDataStoreStatus> {
        self.status.as_ref()
    }
    /// <p>The advanced event selectors that were used to select events for the data store.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.advanced_event_selectors.is_none()`.
    #[deprecated(note = "AdvancedEventSelectors is no longer returned by ListEventDataStores")]
    pub fn advanced_event_selectors(&self) -> &[crate::types::AdvancedEventSelector] {
        self.advanced_event_selectors.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether the event data store includes events from all Regions, or only from the Region in which it was created.</p>
    #[deprecated(note = "MultiRegionEnabled is no longer returned by ListEventDataStores")]
    pub fn multi_region_enabled(&self) -> ::std::option::Option<bool> {
        self.multi_region_enabled
    }
    /// <p>Indicates that an event data store is collecting logged events for an organization.</p>
    #[deprecated(note = "OrganizationEnabled is no longer returned by ListEventDataStores")]
    pub fn organization_enabled(&self) -> ::std::option::Option<bool> {
        self.organization_enabled
    }
    /// <p>The retention period, in days.</p>
    #[deprecated(note = "RetentionPeriod is no longer returned by ListEventDataStores")]
    pub fn retention_period(&self) -> ::std::option::Option<i32> {
        self.retention_period
    }
    /// <p>The timestamp of the event data store's creation.</p>
    #[deprecated(note = "CreatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The timestamp showing when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    #[deprecated(note = "UpdatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn updated_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_timestamp.as_ref()
    }
}
impl EventDataStore {
    /// Creates a new builder-style object to manufacture [`EventDataStore`](crate::types::EventDataStore).
    pub fn builder() -> crate::types::builders::EventDataStoreBuilder {
        crate::types::builders::EventDataStoreBuilder::default()
    }
}

/// A builder for [`EventDataStore`](crate::types::EventDataStore).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EventDataStoreBuilder {
    pub(crate) event_data_store_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) termination_protection_enabled: ::std::option::Option<bool>,
    pub(crate) status: ::std::option::Option<crate::types::EventDataStoreStatus>,
    pub(crate) advanced_event_selectors: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>,
    pub(crate) multi_region_enabled: ::std::option::Option<bool>,
    pub(crate) organization_enabled: ::std::option::Option<bool>,
    pub(crate) retention_period: ::std::option::Option<i32>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl EventDataStoreBuilder {
    /// <p>The ARN of the event data store.</p>
    pub fn event_data_store_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_data_store_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the event data store.</p>
    pub fn set_event_data_store_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_data_store_arn = input;
        self
    }
    /// <p>The ARN of the event data store.</p>
    pub fn get_event_data_store_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_data_store_arn
    }
    /// <p>The name of the event data store.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the event data store.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the event data store.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Indicates whether the event data store is protected from termination.</p>
    #[deprecated(note = "TerminationProtectionEnabled is no longer returned by ListEventDataStores")]
    pub fn termination_protection_enabled(mut self, input: bool) -> Self {
        self.termination_protection_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the event data store is protected from termination.</p>
    #[deprecated(note = "TerminationProtectionEnabled is no longer returned by ListEventDataStores")]
    pub fn set_termination_protection_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.termination_protection_enabled = input;
        self
    }
    /// <p>Indicates whether the event data store is protected from termination.</p>
    #[deprecated(note = "TerminationProtectionEnabled is no longer returned by ListEventDataStores")]
    pub fn get_termination_protection_enabled(&self) -> &::std::option::Option<bool> {
        &self.termination_protection_enabled
    }
    /// <p>The status of an event data store.</p>
    #[deprecated(note = "Status is no longer returned by ListEventDataStores")]
    pub fn status(mut self, input: crate::types::EventDataStoreStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of an event data store.</p>
    #[deprecated(note = "Status is no longer returned by ListEventDataStores")]
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::EventDataStoreStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of an event data store.</p>
    #[deprecated(note = "Status is no longer returned by ListEventDataStores")]
    pub fn get_status(&self) -> &::std::option::Option<crate::types::EventDataStoreStatus> {
        &self.status
    }
    /// Appends an item to `advanced_event_selectors`.
    ///
    /// To override the contents of this collection use [`set_advanced_event_selectors`](Self::set_advanced_event_selectors).
    ///
    /// <p>The advanced event selectors that were used to select events for the data store.</p>
    #[deprecated(note = "AdvancedEventSelectors is no longer returned by ListEventDataStores")]
    pub fn advanced_event_selectors(mut self, input: crate::types::AdvancedEventSelector) -> Self {
        let mut v = self.advanced_event_selectors.unwrap_or_default();
        v.push(input);
        self.advanced_event_selectors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The advanced event selectors that were used to select events for the data store.</p>
    #[deprecated(note = "AdvancedEventSelectors is no longer returned by ListEventDataStores")]
    pub fn set_advanced_event_selectors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>) -> Self {
        self.advanced_event_selectors = input;
        self
    }
    /// <p>The advanced event selectors that were used to select events for the data store.</p>
    #[deprecated(note = "AdvancedEventSelectors is no longer returned by ListEventDataStores")]
    pub fn get_advanced_event_selectors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>> {
        &self.advanced_event_selectors
    }
    /// <p>Indicates whether the event data store includes events from all Regions, or only from the Region in which it was created.</p>
    #[deprecated(note = "MultiRegionEnabled is no longer returned by ListEventDataStores")]
    pub fn multi_region_enabled(mut self, input: bool) -> Self {
        self.multi_region_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the event data store includes events from all Regions, or only from the Region in which it was created.</p>
    #[deprecated(note = "MultiRegionEnabled is no longer returned by ListEventDataStores")]
    pub fn set_multi_region_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.multi_region_enabled = input;
        self
    }
    /// <p>Indicates whether the event data store includes events from all Regions, or only from the Region in which it was created.</p>
    #[deprecated(note = "MultiRegionEnabled is no longer returned by ListEventDataStores")]
    pub fn get_multi_region_enabled(&self) -> &::std::option::Option<bool> {
        &self.multi_region_enabled
    }
    /// <p>Indicates that an event data store is collecting logged events for an organization.</p>
    #[deprecated(note = "OrganizationEnabled is no longer returned by ListEventDataStores")]
    pub fn organization_enabled(mut self, input: bool) -> Self {
        self.organization_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates that an event data store is collecting logged events for an organization.</p>
    #[deprecated(note = "OrganizationEnabled is no longer returned by ListEventDataStores")]
    pub fn set_organization_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.organization_enabled = input;
        self
    }
    /// <p>Indicates that an event data store is collecting logged events for an organization.</p>
    #[deprecated(note = "OrganizationEnabled is no longer returned by ListEventDataStores")]
    pub fn get_organization_enabled(&self) -> &::std::option::Option<bool> {
        &self.organization_enabled
    }
    /// <p>The retention period, in days.</p>
    #[deprecated(note = "RetentionPeriod is no longer returned by ListEventDataStores")]
    pub fn retention_period(mut self, input: i32) -> Self {
        self.retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The retention period, in days.</p>
    #[deprecated(note = "RetentionPeriod is no longer returned by ListEventDataStores")]
    pub fn set_retention_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retention_period = input;
        self
    }
    /// <p>The retention period, in days.</p>
    #[deprecated(note = "RetentionPeriod is no longer returned by ListEventDataStores")]
    pub fn get_retention_period(&self) -> &::std::option::Option<i32> {
        &self.retention_period
    }
    /// <p>The timestamp of the event data store's creation.</p>
    #[deprecated(note = "CreatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of the event data store's creation.</p>
    #[deprecated(note = "CreatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The timestamp of the event data store's creation.</p>
    #[deprecated(note = "CreatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The timestamp showing when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    #[deprecated(note = "UpdatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn updated_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp showing when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    #[deprecated(note = "UpdatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn set_updated_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_timestamp = input;
        self
    }
    /// <p>The timestamp showing when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    #[deprecated(note = "UpdatedTimestamp is no longer returned by ListEventDataStores")]
    pub fn get_updated_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_timestamp
    }
    /// Consumes the builder and constructs a [`EventDataStore`](crate::types::EventDataStore).
    pub fn build(self) -> crate::types::EventDataStore {
        crate::types::EventDataStore {
            event_data_store_arn: self.event_data_store_arn,
            name: self.name,
            termination_protection_enabled: self.termination_protection_enabled,
            status: self.status,
            advanced_event_selectors: self.advanced_event_selectors,
            multi_region_enabled: self.multi_region_enabled,
            organization_enabled: self.organization_enabled,
            retention_period: self.retention_period,
            created_timestamp: self.created_timestamp,
            updated_timestamp: self.updated_timestamp,
        }
    }
}
