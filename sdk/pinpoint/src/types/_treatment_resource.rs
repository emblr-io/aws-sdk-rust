// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the settings for a campaign treatment. A <i>treatment</i> is a variation of a campaign that's used for A/B testing of a campaign.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TreatmentResource {
    /// <p>The delivery configuration settings for sending the treatment through a custom channel. This object is required if the MessageConfiguration object for the treatment specifies a CustomMessage object.</p>
    pub custom_delivery_configuration: ::std::option::Option<crate::types::CustomDeliveryConfiguration>,
    /// <p>The unique identifier for the treatment.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The message configuration settings for the treatment.</p>
    pub message_configuration: ::std::option::Option<crate::types::MessageConfiguration>,
    /// <p>The schedule settings for the treatment.</p>
    pub schedule: ::std::option::Option<crate::types::Schedule>,
    /// <p>The allocated percentage of users (segment members) that the treatment is sent to.</p>
    pub size_percent: ::std::option::Option<i32>,
    /// <p>The current status of the treatment.</p>
    pub state: ::std::option::Option<crate::types::CampaignState>,
    /// <p>The message template to use for the treatment.</p>
    pub template_configuration: ::std::option::Option<crate::types::TemplateConfiguration>,
    /// <p>The custom description of the treatment.</p>
    pub treatment_description: ::std::option::Option<::std::string::String>,
    /// <p>The custom name of the treatment.</p>
    pub treatment_name: ::std::option::Option<::std::string::String>,
}
impl TreatmentResource {
    /// <p>The delivery configuration settings for sending the treatment through a custom channel. This object is required if the MessageConfiguration object for the treatment specifies a CustomMessage object.</p>
    pub fn custom_delivery_configuration(&self) -> ::std::option::Option<&crate::types::CustomDeliveryConfiguration> {
        self.custom_delivery_configuration.as_ref()
    }
    /// <p>The unique identifier for the treatment.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The message configuration settings for the treatment.</p>
    pub fn message_configuration(&self) -> ::std::option::Option<&crate::types::MessageConfiguration> {
        self.message_configuration.as_ref()
    }
    /// <p>The schedule settings for the treatment.</p>
    pub fn schedule(&self) -> ::std::option::Option<&crate::types::Schedule> {
        self.schedule.as_ref()
    }
    /// <p>The allocated percentage of users (segment members) that the treatment is sent to.</p>
    pub fn size_percent(&self) -> ::std::option::Option<i32> {
        self.size_percent
    }
    /// <p>The current status of the treatment.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::CampaignState> {
        self.state.as_ref()
    }
    /// <p>The message template to use for the treatment.</p>
    pub fn template_configuration(&self) -> ::std::option::Option<&crate::types::TemplateConfiguration> {
        self.template_configuration.as_ref()
    }
    /// <p>The custom description of the treatment.</p>
    pub fn treatment_description(&self) -> ::std::option::Option<&str> {
        self.treatment_description.as_deref()
    }
    /// <p>The custom name of the treatment.</p>
    pub fn treatment_name(&self) -> ::std::option::Option<&str> {
        self.treatment_name.as_deref()
    }
}
impl TreatmentResource {
    /// Creates a new builder-style object to manufacture [`TreatmentResource`](crate::types::TreatmentResource).
    pub fn builder() -> crate::types::builders::TreatmentResourceBuilder {
        crate::types::builders::TreatmentResourceBuilder::default()
    }
}

/// A builder for [`TreatmentResource`](crate::types::TreatmentResource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TreatmentResourceBuilder {
    pub(crate) custom_delivery_configuration: ::std::option::Option<crate::types::CustomDeliveryConfiguration>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) message_configuration: ::std::option::Option<crate::types::MessageConfiguration>,
    pub(crate) schedule: ::std::option::Option<crate::types::Schedule>,
    pub(crate) size_percent: ::std::option::Option<i32>,
    pub(crate) state: ::std::option::Option<crate::types::CampaignState>,
    pub(crate) template_configuration: ::std::option::Option<crate::types::TemplateConfiguration>,
    pub(crate) treatment_description: ::std::option::Option<::std::string::String>,
    pub(crate) treatment_name: ::std::option::Option<::std::string::String>,
}
impl TreatmentResourceBuilder {
    /// <p>The delivery configuration settings for sending the treatment through a custom channel. This object is required if the MessageConfiguration object for the treatment specifies a CustomMessage object.</p>
    pub fn custom_delivery_configuration(mut self, input: crate::types::CustomDeliveryConfiguration) -> Self {
        self.custom_delivery_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The delivery configuration settings for sending the treatment through a custom channel. This object is required if the MessageConfiguration object for the treatment specifies a CustomMessage object.</p>
    pub fn set_custom_delivery_configuration(mut self, input: ::std::option::Option<crate::types::CustomDeliveryConfiguration>) -> Self {
        self.custom_delivery_configuration = input;
        self
    }
    /// <p>The delivery configuration settings for sending the treatment through a custom channel. This object is required if the MessageConfiguration object for the treatment specifies a CustomMessage object.</p>
    pub fn get_custom_delivery_configuration(&self) -> &::std::option::Option<crate::types::CustomDeliveryConfiguration> {
        &self.custom_delivery_configuration
    }
    /// <p>The unique identifier for the treatment.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the treatment.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the treatment.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The message configuration settings for the treatment.</p>
    pub fn message_configuration(mut self, input: crate::types::MessageConfiguration) -> Self {
        self.message_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The message configuration settings for the treatment.</p>
    pub fn set_message_configuration(mut self, input: ::std::option::Option<crate::types::MessageConfiguration>) -> Self {
        self.message_configuration = input;
        self
    }
    /// <p>The message configuration settings for the treatment.</p>
    pub fn get_message_configuration(&self) -> &::std::option::Option<crate::types::MessageConfiguration> {
        &self.message_configuration
    }
    /// <p>The schedule settings for the treatment.</p>
    pub fn schedule(mut self, input: crate::types::Schedule) -> Self {
        self.schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>The schedule settings for the treatment.</p>
    pub fn set_schedule(mut self, input: ::std::option::Option<crate::types::Schedule>) -> Self {
        self.schedule = input;
        self
    }
    /// <p>The schedule settings for the treatment.</p>
    pub fn get_schedule(&self) -> &::std::option::Option<crate::types::Schedule> {
        &self.schedule
    }
    /// <p>The allocated percentage of users (segment members) that the treatment is sent to.</p>
    /// This field is required.
    pub fn size_percent(mut self, input: i32) -> Self {
        self.size_percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>The allocated percentage of users (segment members) that the treatment is sent to.</p>
    pub fn set_size_percent(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_percent = input;
        self
    }
    /// <p>The allocated percentage of users (segment members) that the treatment is sent to.</p>
    pub fn get_size_percent(&self) -> &::std::option::Option<i32> {
        &self.size_percent
    }
    /// <p>The current status of the treatment.</p>
    pub fn state(mut self, input: crate::types::CampaignState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the treatment.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::CampaignState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current status of the treatment.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::CampaignState> {
        &self.state
    }
    /// <p>The message template to use for the treatment.</p>
    pub fn template_configuration(mut self, input: crate::types::TemplateConfiguration) -> Self {
        self.template_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The message template to use for the treatment.</p>
    pub fn set_template_configuration(mut self, input: ::std::option::Option<crate::types::TemplateConfiguration>) -> Self {
        self.template_configuration = input;
        self
    }
    /// <p>The message template to use for the treatment.</p>
    pub fn get_template_configuration(&self) -> &::std::option::Option<crate::types::TemplateConfiguration> {
        &self.template_configuration
    }
    /// <p>The custom description of the treatment.</p>
    pub fn treatment_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.treatment_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom description of the treatment.</p>
    pub fn set_treatment_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.treatment_description = input;
        self
    }
    /// <p>The custom description of the treatment.</p>
    pub fn get_treatment_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.treatment_description
    }
    /// <p>The custom name of the treatment.</p>
    pub fn treatment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.treatment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom name of the treatment.</p>
    pub fn set_treatment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.treatment_name = input;
        self
    }
    /// <p>The custom name of the treatment.</p>
    pub fn get_treatment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.treatment_name
    }
    /// Consumes the builder and constructs a [`TreatmentResource`](crate::types::TreatmentResource).
    pub fn build(self) -> crate::types::TreatmentResource {
        crate::types::TreatmentResource {
            custom_delivery_configuration: self.custom_delivery_configuration,
            id: self.id,
            message_configuration: self.message_configuration,
            schedule: self.schedule,
            size_percent: self.size_percent,
            state: self.state,
            template_configuration: self.template_configuration,
            treatment_description: self.treatment_description,
            treatment_name: self.treatment_name,
        }
    }
}
