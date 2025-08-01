// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEventDataStoreOutput {
    /// <p>The ARN of the event data store.</p>
    pub event_data_store_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the event data store.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The status of event data store creation.</p>
    pub status: ::std::option::Option<crate::types::EventDataStoreStatus>,
    /// <p>The advanced event selectors that were used to select the events for the data store.</p>
    pub advanced_event_selectors: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>,
    /// <p>Indicates whether the event data store collects events from all Regions, or only from the Region in which it was created.</p>
    pub multi_region_enabled: ::std::option::Option<bool>,
    /// <p>Indicates whether an event data store is collecting logged events for an organization in Organizations.</p>
    pub organization_enabled: ::std::option::Option<bool>,
    /// <p>The retention period of an event data store, in days.</p>
    pub retention_period: ::std::option::Option<i32>,
    /// <p>Indicates whether termination protection is enabled for the event data store.</p>
    pub termination_protection_enabled: ::std::option::Option<bool>,
    /// <p>A list of tags.</p>
    pub tags_list: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The timestamp that shows when the event data store was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp that shows when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    pub updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies the KMS key ID that encrypts the events delivered by CloudTrail. The value is a fully specified ARN to a KMS key in the following format.</p>
    /// <p><code>arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012</code></p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The billing mode for the event data store.</p>
    pub billing_mode: ::std::option::Option<crate::types::BillingMode>,
    _request_id: Option<String>,
}
impl CreateEventDataStoreOutput {
    /// <p>The ARN of the event data store.</p>
    pub fn event_data_store_arn(&self) -> ::std::option::Option<&str> {
        self.event_data_store_arn.as_deref()
    }
    /// <p>The name of the event data store.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The status of event data store creation.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::EventDataStoreStatus> {
        self.status.as_ref()
    }
    /// <p>The advanced event selectors that were used to select the events for the data store.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.advanced_event_selectors.is_none()`.
    pub fn advanced_event_selectors(&self) -> &[crate::types::AdvancedEventSelector] {
        self.advanced_event_selectors.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether the event data store collects events from all Regions, or only from the Region in which it was created.</p>
    pub fn multi_region_enabled(&self) -> ::std::option::Option<bool> {
        self.multi_region_enabled
    }
    /// <p>Indicates whether an event data store is collecting logged events for an organization in Organizations.</p>
    pub fn organization_enabled(&self) -> ::std::option::Option<bool> {
        self.organization_enabled
    }
    /// <p>The retention period of an event data store, in days.</p>
    pub fn retention_period(&self) -> ::std::option::Option<i32> {
        self.retention_period
    }
    /// <p>Indicates whether termination protection is enabled for the event data store.</p>
    pub fn termination_protection_enabled(&self) -> ::std::option::Option<bool> {
        self.termination_protection_enabled
    }
    /// <p>A list of tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags_list.is_none()`.
    pub fn tags_list(&self) -> &[crate::types::Tag] {
        self.tags_list.as_deref().unwrap_or_default()
    }
    /// <p>The timestamp that shows when the event data store was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The timestamp that shows when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    pub fn updated_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_timestamp.as_ref()
    }
    /// <p>Specifies the KMS key ID that encrypts the events delivered by CloudTrail. The value is a fully specified ARN to a KMS key in the following format.</p>
    /// <p><code>arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012</code></p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The billing mode for the event data store.</p>
    pub fn billing_mode(&self) -> ::std::option::Option<&crate::types::BillingMode> {
        self.billing_mode.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEventDataStoreOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEventDataStoreOutput {
    /// Creates a new builder-style object to manufacture [`CreateEventDataStoreOutput`](crate::operation::create_event_data_store::CreateEventDataStoreOutput).
    pub fn builder() -> crate::operation::create_event_data_store::builders::CreateEventDataStoreOutputBuilder {
        crate::operation::create_event_data_store::builders::CreateEventDataStoreOutputBuilder::default()
    }
}

/// A builder for [`CreateEventDataStoreOutput`](crate::operation::create_event_data_store::CreateEventDataStoreOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEventDataStoreOutputBuilder {
    pub(crate) event_data_store_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::EventDataStoreStatus>,
    pub(crate) advanced_event_selectors: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>,
    pub(crate) multi_region_enabled: ::std::option::Option<bool>,
    pub(crate) organization_enabled: ::std::option::Option<bool>,
    pub(crate) retention_period: ::std::option::Option<i32>,
    pub(crate) termination_protection_enabled: ::std::option::Option<bool>,
    pub(crate) tags_list: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) billing_mode: ::std::option::Option<crate::types::BillingMode>,
    _request_id: Option<String>,
}
impl CreateEventDataStoreOutputBuilder {
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
    /// <p>The status of event data store creation.</p>
    pub fn status(mut self, input: crate::types::EventDataStoreStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of event data store creation.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::EventDataStoreStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of event data store creation.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::EventDataStoreStatus> {
        &self.status
    }
    /// Appends an item to `advanced_event_selectors`.
    ///
    /// To override the contents of this collection use [`set_advanced_event_selectors`](Self::set_advanced_event_selectors).
    ///
    /// <p>The advanced event selectors that were used to select the events for the data store.</p>
    pub fn advanced_event_selectors(mut self, input: crate::types::AdvancedEventSelector) -> Self {
        let mut v = self.advanced_event_selectors.unwrap_or_default();
        v.push(input);
        self.advanced_event_selectors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The advanced event selectors that were used to select the events for the data store.</p>
    pub fn set_advanced_event_selectors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>>) -> Self {
        self.advanced_event_selectors = input;
        self
    }
    /// <p>The advanced event selectors that were used to select the events for the data store.</p>
    pub fn get_advanced_event_selectors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdvancedEventSelector>> {
        &self.advanced_event_selectors
    }
    /// <p>Indicates whether the event data store collects events from all Regions, or only from the Region in which it was created.</p>
    pub fn multi_region_enabled(mut self, input: bool) -> Self {
        self.multi_region_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the event data store collects events from all Regions, or only from the Region in which it was created.</p>
    pub fn set_multi_region_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.multi_region_enabled = input;
        self
    }
    /// <p>Indicates whether the event data store collects events from all Regions, or only from the Region in which it was created.</p>
    pub fn get_multi_region_enabled(&self) -> &::std::option::Option<bool> {
        &self.multi_region_enabled
    }
    /// <p>Indicates whether an event data store is collecting logged events for an organization in Organizations.</p>
    pub fn organization_enabled(mut self, input: bool) -> Self {
        self.organization_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether an event data store is collecting logged events for an organization in Organizations.</p>
    pub fn set_organization_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.organization_enabled = input;
        self
    }
    /// <p>Indicates whether an event data store is collecting logged events for an organization in Organizations.</p>
    pub fn get_organization_enabled(&self) -> &::std::option::Option<bool> {
        &self.organization_enabled
    }
    /// <p>The retention period of an event data store, in days.</p>
    pub fn retention_period(mut self, input: i32) -> Self {
        self.retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The retention period of an event data store, in days.</p>
    pub fn set_retention_period(mut self, input: ::std::option::Option<i32>) -> Self {
        self.retention_period = input;
        self
    }
    /// <p>The retention period of an event data store, in days.</p>
    pub fn get_retention_period(&self) -> &::std::option::Option<i32> {
        &self.retention_period
    }
    /// <p>Indicates whether termination protection is enabled for the event data store.</p>
    pub fn termination_protection_enabled(mut self, input: bool) -> Self {
        self.termination_protection_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether termination protection is enabled for the event data store.</p>
    pub fn set_termination_protection_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.termination_protection_enabled = input;
        self
    }
    /// <p>Indicates whether termination protection is enabled for the event data store.</p>
    pub fn get_termination_protection_enabled(&self) -> &::std::option::Option<bool> {
        &self.termination_protection_enabled
    }
    /// Appends an item to `tags_list`.
    ///
    /// To override the contents of this collection use [`set_tags_list`](Self::set_tags_list).
    ///
    /// <p>A list of tags.</p>
    pub fn tags_list(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags_list.unwrap_or_default();
        v.push(input);
        self.tags_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags.</p>
    pub fn set_tags_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags_list = input;
        self
    }
    /// <p>A list of tags.</p>
    pub fn get_tags_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags_list
    }
    /// <p>The timestamp that shows when the event data store was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that shows when the event data store was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The timestamp that shows when the event data store was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The timestamp that shows when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    pub fn updated_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that shows when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    pub fn set_updated_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_timestamp = input;
        self
    }
    /// <p>The timestamp that shows when an event data store was updated, if applicable. <code>UpdatedTimestamp</code> is always either the same or newer than the time shown in <code>CreatedTimestamp</code>.</p>
    pub fn get_updated_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_timestamp
    }
    /// <p>Specifies the KMS key ID that encrypts the events delivered by CloudTrail. The value is a fully specified ARN to a KMS key in the following format.</p>
    /// <p><code>arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012</code></p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the KMS key ID that encrypts the events delivered by CloudTrail. The value is a fully specified ARN to a KMS key in the following format.</p>
    /// <p><code>arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012</code></p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>Specifies the KMS key ID that encrypts the events delivered by CloudTrail. The value is a fully specified ARN to a KMS key in the following format.</p>
    /// <p><code>arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012</code></p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The billing mode for the event data store.</p>
    pub fn billing_mode(mut self, input: crate::types::BillingMode) -> Self {
        self.billing_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The billing mode for the event data store.</p>
    pub fn set_billing_mode(mut self, input: ::std::option::Option<crate::types::BillingMode>) -> Self {
        self.billing_mode = input;
        self
    }
    /// <p>The billing mode for the event data store.</p>
    pub fn get_billing_mode(&self) -> &::std::option::Option<crate::types::BillingMode> {
        &self.billing_mode
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateEventDataStoreOutput`](crate::operation::create_event_data_store::CreateEventDataStoreOutput).
    pub fn build(self) -> crate::operation::create_event_data_store::CreateEventDataStoreOutput {
        crate::operation::create_event_data_store::CreateEventDataStoreOutput {
            event_data_store_arn: self.event_data_store_arn,
            name: self.name,
            status: self.status,
            advanced_event_selectors: self.advanced_event_selectors,
            multi_region_enabled: self.multi_region_enabled,
            organization_enabled: self.organization_enabled,
            retention_period: self.retention_period,
            termination_protection_enabled: self.termination_protection_enabled,
            tags_list: self.tags_list,
            created_timestamp: self.created_timestamp,
            updated_timestamp: self.updated_timestamp,
            kms_key_id: self.kms_key_id,
            billing_mode: self.billing_mode,
            _request_id: self._request_id,
        }
    }
}
