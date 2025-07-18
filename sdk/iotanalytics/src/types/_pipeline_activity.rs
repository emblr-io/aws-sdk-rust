// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An activity that performs a transformation on a message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PipelineActivity {
    /// <p>Determines the source of the messages to be processed.</p>
    pub channel: ::std::option::Option<crate::types::ChannelActivity>,
    /// <p>Runs a Lambda function to modify the message.</p>
    pub lambda: ::std::option::Option<crate::types::LambdaActivity>,
    /// <p>Specifies where to store the processed message data.</p>
    pub datastore: ::std::option::Option<crate::types::DatastoreActivity>,
    /// <p>Adds other attributes based on existing attributes in the message.</p>
    pub add_attributes: ::std::option::Option<crate::types::AddAttributesActivity>,
    /// <p>Removes attributes from a message.</p>
    pub remove_attributes: ::std::option::Option<crate::types::RemoveAttributesActivity>,
    /// <p>Used to create a new message using only the specified attributes from the original message.</p>
    pub select_attributes: ::std::option::Option<crate::types::SelectAttributesActivity>,
    /// <p>Filters a message based on its attributes.</p>
    pub filter: ::std::option::Option<crate::types::FilterActivity>,
    /// <p>Computes an arithmetic expression using the message's attributes and adds it to the message.</p>
    pub math: ::std::option::Option<crate::types::MathActivity>,
    /// <p>Adds data from the IoT device registry to your message.</p>
    pub device_registry_enrich: ::std::option::Option<crate::types::DeviceRegistryEnrichActivity>,
    /// <p>Adds information from the IoT Device Shadow service to a message.</p>
    pub device_shadow_enrich: ::std::option::Option<crate::types::DeviceShadowEnrichActivity>,
}
impl PipelineActivity {
    /// <p>Determines the source of the messages to be processed.</p>
    pub fn channel(&self) -> ::std::option::Option<&crate::types::ChannelActivity> {
        self.channel.as_ref()
    }
    /// <p>Runs a Lambda function to modify the message.</p>
    pub fn lambda(&self) -> ::std::option::Option<&crate::types::LambdaActivity> {
        self.lambda.as_ref()
    }
    /// <p>Specifies where to store the processed message data.</p>
    pub fn datastore(&self) -> ::std::option::Option<&crate::types::DatastoreActivity> {
        self.datastore.as_ref()
    }
    /// <p>Adds other attributes based on existing attributes in the message.</p>
    pub fn add_attributes(&self) -> ::std::option::Option<&crate::types::AddAttributesActivity> {
        self.add_attributes.as_ref()
    }
    /// <p>Removes attributes from a message.</p>
    pub fn remove_attributes(&self) -> ::std::option::Option<&crate::types::RemoveAttributesActivity> {
        self.remove_attributes.as_ref()
    }
    /// <p>Used to create a new message using only the specified attributes from the original message.</p>
    pub fn select_attributes(&self) -> ::std::option::Option<&crate::types::SelectAttributesActivity> {
        self.select_attributes.as_ref()
    }
    /// <p>Filters a message based on its attributes.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::FilterActivity> {
        self.filter.as_ref()
    }
    /// <p>Computes an arithmetic expression using the message's attributes and adds it to the message.</p>
    pub fn math(&self) -> ::std::option::Option<&crate::types::MathActivity> {
        self.math.as_ref()
    }
    /// <p>Adds data from the IoT device registry to your message.</p>
    pub fn device_registry_enrich(&self) -> ::std::option::Option<&crate::types::DeviceRegistryEnrichActivity> {
        self.device_registry_enrich.as_ref()
    }
    /// <p>Adds information from the IoT Device Shadow service to a message.</p>
    pub fn device_shadow_enrich(&self) -> ::std::option::Option<&crate::types::DeviceShadowEnrichActivity> {
        self.device_shadow_enrich.as_ref()
    }
}
impl PipelineActivity {
    /// Creates a new builder-style object to manufacture [`PipelineActivity`](crate::types::PipelineActivity).
    pub fn builder() -> crate::types::builders::PipelineActivityBuilder {
        crate::types::builders::PipelineActivityBuilder::default()
    }
}

/// A builder for [`PipelineActivity`](crate::types::PipelineActivity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipelineActivityBuilder {
    pub(crate) channel: ::std::option::Option<crate::types::ChannelActivity>,
    pub(crate) lambda: ::std::option::Option<crate::types::LambdaActivity>,
    pub(crate) datastore: ::std::option::Option<crate::types::DatastoreActivity>,
    pub(crate) add_attributes: ::std::option::Option<crate::types::AddAttributesActivity>,
    pub(crate) remove_attributes: ::std::option::Option<crate::types::RemoveAttributesActivity>,
    pub(crate) select_attributes: ::std::option::Option<crate::types::SelectAttributesActivity>,
    pub(crate) filter: ::std::option::Option<crate::types::FilterActivity>,
    pub(crate) math: ::std::option::Option<crate::types::MathActivity>,
    pub(crate) device_registry_enrich: ::std::option::Option<crate::types::DeviceRegistryEnrichActivity>,
    pub(crate) device_shadow_enrich: ::std::option::Option<crate::types::DeviceShadowEnrichActivity>,
}
impl PipelineActivityBuilder {
    /// <p>Determines the source of the messages to be processed.</p>
    pub fn channel(mut self, input: crate::types::ChannelActivity) -> Self {
        self.channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines the source of the messages to be processed.</p>
    pub fn set_channel(mut self, input: ::std::option::Option<crate::types::ChannelActivity>) -> Self {
        self.channel = input;
        self
    }
    /// <p>Determines the source of the messages to be processed.</p>
    pub fn get_channel(&self) -> &::std::option::Option<crate::types::ChannelActivity> {
        &self.channel
    }
    /// <p>Runs a Lambda function to modify the message.</p>
    pub fn lambda(mut self, input: crate::types::LambdaActivity) -> Self {
        self.lambda = ::std::option::Option::Some(input);
        self
    }
    /// <p>Runs a Lambda function to modify the message.</p>
    pub fn set_lambda(mut self, input: ::std::option::Option<crate::types::LambdaActivity>) -> Self {
        self.lambda = input;
        self
    }
    /// <p>Runs a Lambda function to modify the message.</p>
    pub fn get_lambda(&self) -> &::std::option::Option<crate::types::LambdaActivity> {
        &self.lambda
    }
    /// <p>Specifies where to store the processed message data.</p>
    pub fn datastore(mut self, input: crate::types::DatastoreActivity) -> Self {
        self.datastore = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies where to store the processed message data.</p>
    pub fn set_datastore(mut self, input: ::std::option::Option<crate::types::DatastoreActivity>) -> Self {
        self.datastore = input;
        self
    }
    /// <p>Specifies where to store the processed message data.</p>
    pub fn get_datastore(&self) -> &::std::option::Option<crate::types::DatastoreActivity> {
        &self.datastore
    }
    /// <p>Adds other attributes based on existing attributes in the message.</p>
    pub fn add_attributes(mut self, input: crate::types::AddAttributesActivity) -> Self {
        self.add_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Adds other attributes based on existing attributes in the message.</p>
    pub fn set_add_attributes(mut self, input: ::std::option::Option<crate::types::AddAttributesActivity>) -> Self {
        self.add_attributes = input;
        self
    }
    /// <p>Adds other attributes based on existing attributes in the message.</p>
    pub fn get_add_attributes(&self) -> &::std::option::Option<crate::types::AddAttributesActivity> {
        &self.add_attributes
    }
    /// <p>Removes attributes from a message.</p>
    pub fn remove_attributes(mut self, input: crate::types::RemoveAttributesActivity) -> Self {
        self.remove_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Removes attributes from a message.</p>
    pub fn set_remove_attributes(mut self, input: ::std::option::Option<crate::types::RemoveAttributesActivity>) -> Self {
        self.remove_attributes = input;
        self
    }
    /// <p>Removes attributes from a message.</p>
    pub fn get_remove_attributes(&self) -> &::std::option::Option<crate::types::RemoveAttributesActivity> {
        &self.remove_attributes
    }
    /// <p>Used to create a new message using only the specified attributes from the original message.</p>
    pub fn select_attributes(mut self, input: crate::types::SelectAttributesActivity) -> Self {
        self.select_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Used to create a new message using only the specified attributes from the original message.</p>
    pub fn set_select_attributes(mut self, input: ::std::option::Option<crate::types::SelectAttributesActivity>) -> Self {
        self.select_attributes = input;
        self
    }
    /// <p>Used to create a new message using only the specified attributes from the original message.</p>
    pub fn get_select_attributes(&self) -> &::std::option::Option<crate::types::SelectAttributesActivity> {
        &self.select_attributes
    }
    /// <p>Filters a message based on its attributes.</p>
    pub fn filter(mut self, input: crate::types::FilterActivity) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters a message based on its attributes.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::FilterActivity>) -> Self {
        self.filter = input;
        self
    }
    /// <p>Filters a message based on its attributes.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::FilterActivity> {
        &self.filter
    }
    /// <p>Computes an arithmetic expression using the message's attributes and adds it to the message.</p>
    pub fn math(mut self, input: crate::types::MathActivity) -> Self {
        self.math = ::std::option::Option::Some(input);
        self
    }
    /// <p>Computes an arithmetic expression using the message's attributes and adds it to the message.</p>
    pub fn set_math(mut self, input: ::std::option::Option<crate::types::MathActivity>) -> Self {
        self.math = input;
        self
    }
    /// <p>Computes an arithmetic expression using the message's attributes and adds it to the message.</p>
    pub fn get_math(&self) -> &::std::option::Option<crate::types::MathActivity> {
        &self.math
    }
    /// <p>Adds data from the IoT device registry to your message.</p>
    pub fn device_registry_enrich(mut self, input: crate::types::DeviceRegistryEnrichActivity) -> Self {
        self.device_registry_enrich = ::std::option::Option::Some(input);
        self
    }
    /// <p>Adds data from the IoT device registry to your message.</p>
    pub fn set_device_registry_enrich(mut self, input: ::std::option::Option<crate::types::DeviceRegistryEnrichActivity>) -> Self {
        self.device_registry_enrich = input;
        self
    }
    /// <p>Adds data from the IoT device registry to your message.</p>
    pub fn get_device_registry_enrich(&self) -> &::std::option::Option<crate::types::DeviceRegistryEnrichActivity> {
        &self.device_registry_enrich
    }
    /// <p>Adds information from the IoT Device Shadow service to a message.</p>
    pub fn device_shadow_enrich(mut self, input: crate::types::DeviceShadowEnrichActivity) -> Self {
        self.device_shadow_enrich = ::std::option::Option::Some(input);
        self
    }
    /// <p>Adds information from the IoT Device Shadow service to a message.</p>
    pub fn set_device_shadow_enrich(mut self, input: ::std::option::Option<crate::types::DeviceShadowEnrichActivity>) -> Self {
        self.device_shadow_enrich = input;
        self
    }
    /// <p>Adds information from the IoT Device Shadow service to a message.</p>
    pub fn get_device_shadow_enrich(&self) -> &::std::option::Option<crate::types::DeviceShadowEnrichActivity> {
        &self.device_shadow_enrich
    }
    /// Consumes the builder and constructs a [`PipelineActivity`](crate::types::PipelineActivity).
    pub fn build(self) -> crate::types::PipelineActivity {
        crate::types::PipelineActivity {
            channel: self.channel,
            lambda: self.lambda,
            datastore: self.datastore,
            add_attributes: self.add_attributes,
            remove_attributes: self.remove_attributes,
            select_attributes: self.select_attributes,
            filter: self.filter,
            math: self.math,
            device_registry_enrich: self.device_registry_enrich,
            device_shadow_enrich: self.device_shadow_enrich,
        }
    }
}
