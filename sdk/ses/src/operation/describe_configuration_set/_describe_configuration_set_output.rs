// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the details of a configuration set. Configuration sets enable you to publish email sending events. For information about using configuration sets, see the <a href="https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html">Amazon SES Developer Guide</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConfigurationSetOutput {
    /// <p>The configuration set object associated with the specified configuration set.</p>
    pub configuration_set: ::std::option::Option<crate::types::ConfigurationSet>,
    /// <p>A list of event destinations associated with the configuration set.</p>
    pub event_destinations: ::std::option::Option<::std::vec::Vec<crate::types::EventDestination>>,
    /// <p>The name of the custom open and click tracking domain associated with the configuration set.</p>
    pub tracking_options: ::std::option::Option<crate::types::TrackingOptions>,
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS).</p>
    pub delivery_options: ::std::option::Option<crate::types::DeliveryOptions>,
    /// <p>An object that represents the reputation settings for the configuration set.</p>
    pub reputation_options: ::std::option::Option<crate::types::ReputationOptions>,
    _request_id: Option<String>,
}
impl DescribeConfigurationSetOutput {
    /// <p>The configuration set object associated with the specified configuration set.</p>
    pub fn configuration_set(&self) -> ::std::option::Option<&crate::types::ConfigurationSet> {
        self.configuration_set.as_ref()
    }
    /// <p>A list of event destinations associated with the configuration set.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.event_destinations.is_none()`.
    pub fn event_destinations(&self) -> &[crate::types::EventDestination] {
        self.event_destinations.as_deref().unwrap_or_default()
    }
    /// <p>The name of the custom open and click tracking domain associated with the configuration set.</p>
    pub fn tracking_options(&self) -> ::std::option::Option<&crate::types::TrackingOptions> {
        self.tracking_options.as_ref()
    }
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS).</p>
    pub fn delivery_options(&self) -> ::std::option::Option<&crate::types::DeliveryOptions> {
        self.delivery_options.as_ref()
    }
    /// <p>An object that represents the reputation settings for the configuration set.</p>
    pub fn reputation_options(&self) -> ::std::option::Option<&crate::types::ReputationOptions> {
        self.reputation_options.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeConfigurationSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeConfigurationSetOutput {
    /// Creates a new builder-style object to manufacture [`DescribeConfigurationSetOutput`](crate::operation::describe_configuration_set::DescribeConfigurationSetOutput).
    pub fn builder() -> crate::operation::describe_configuration_set::builders::DescribeConfigurationSetOutputBuilder {
        crate::operation::describe_configuration_set::builders::DescribeConfigurationSetOutputBuilder::default()
    }
}

/// A builder for [`DescribeConfigurationSetOutput`](crate::operation::describe_configuration_set::DescribeConfigurationSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConfigurationSetOutputBuilder {
    pub(crate) configuration_set: ::std::option::Option<crate::types::ConfigurationSet>,
    pub(crate) event_destinations: ::std::option::Option<::std::vec::Vec<crate::types::EventDestination>>,
    pub(crate) tracking_options: ::std::option::Option<crate::types::TrackingOptions>,
    pub(crate) delivery_options: ::std::option::Option<crate::types::DeliveryOptions>,
    pub(crate) reputation_options: ::std::option::Option<crate::types::ReputationOptions>,
    _request_id: Option<String>,
}
impl DescribeConfigurationSetOutputBuilder {
    /// <p>The configuration set object associated with the specified configuration set.</p>
    pub fn configuration_set(mut self, input: crate::types::ConfigurationSet) -> Self {
        self.configuration_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration set object associated with the specified configuration set.</p>
    pub fn set_configuration_set(mut self, input: ::std::option::Option<crate::types::ConfigurationSet>) -> Self {
        self.configuration_set = input;
        self
    }
    /// <p>The configuration set object associated with the specified configuration set.</p>
    pub fn get_configuration_set(&self) -> &::std::option::Option<crate::types::ConfigurationSet> {
        &self.configuration_set
    }
    /// Appends an item to `event_destinations`.
    ///
    /// To override the contents of this collection use [`set_event_destinations`](Self::set_event_destinations).
    ///
    /// <p>A list of event destinations associated with the configuration set.</p>
    pub fn event_destinations(mut self, input: crate::types::EventDestination) -> Self {
        let mut v = self.event_destinations.unwrap_or_default();
        v.push(input);
        self.event_destinations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of event destinations associated with the configuration set.</p>
    pub fn set_event_destinations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventDestination>>) -> Self {
        self.event_destinations = input;
        self
    }
    /// <p>A list of event destinations associated with the configuration set.</p>
    pub fn get_event_destinations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventDestination>> {
        &self.event_destinations
    }
    /// <p>The name of the custom open and click tracking domain associated with the configuration set.</p>
    pub fn tracking_options(mut self, input: crate::types::TrackingOptions) -> Self {
        self.tracking_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the custom open and click tracking domain associated with the configuration set.</p>
    pub fn set_tracking_options(mut self, input: ::std::option::Option<crate::types::TrackingOptions>) -> Self {
        self.tracking_options = input;
        self
    }
    /// <p>The name of the custom open and click tracking domain associated with the configuration set.</p>
    pub fn get_tracking_options(&self) -> &::std::option::Option<crate::types::TrackingOptions> {
        &self.tracking_options
    }
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS).</p>
    pub fn delivery_options(mut self, input: crate::types::DeliveryOptions) -> Self {
        self.delivery_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS).</p>
    pub fn set_delivery_options(mut self, input: ::std::option::Option<crate::types::DeliveryOptions>) -> Self {
        self.delivery_options = input;
        self
    }
    /// <p>Specifies whether messages that use the configuration set are required to use Transport Layer Security (TLS).</p>
    pub fn get_delivery_options(&self) -> &::std::option::Option<crate::types::DeliveryOptions> {
        &self.delivery_options
    }
    /// <p>An object that represents the reputation settings for the configuration set.</p>
    pub fn reputation_options(mut self, input: crate::types::ReputationOptions) -> Self {
        self.reputation_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that represents the reputation settings for the configuration set.</p>
    pub fn set_reputation_options(mut self, input: ::std::option::Option<crate::types::ReputationOptions>) -> Self {
        self.reputation_options = input;
        self
    }
    /// <p>An object that represents the reputation settings for the configuration set.</p>
    pub fn get_reputation_options(&self) -> &::std::option::Option<crate::types::ReputationOptions> {
        &self.reputation_options
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeConfigurationSetOutput`](crate::operation::describe_configuration_set::DescribeConfigurationSetOutput).
    pub fn build(self) -> crate::operation::describe_configuration_set::DescribeConfigurationSetOutput {
        crate::operation::describe_configuration_set::DescribeConfigurationSetOutput {
            configuration_set: self.configuration_set,
            event_destinations: self.event_destinations,
            tracking_options: self.tracking_options,
            delivery_options: self.delivery_options,
            reputation_options: self.reputation_options,
            _request_id: self._request_id,
        }
    }
}
