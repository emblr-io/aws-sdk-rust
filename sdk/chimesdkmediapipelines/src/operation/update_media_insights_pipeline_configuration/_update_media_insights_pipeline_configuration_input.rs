// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateMediaInsightsPipelineConfigurationInput {
    /// <p>The unique identifier for the resource to be updated. Valid values include the name and ARN of the media insights pipeline configuration.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the role used by the service to access Amazon Web Services resources.</p>
    pub resource_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The configuration settings for real-time alerts for the media insights pipeline.</p>
    pub real_time_alert_configuration: ::std::option::Option<crate::types::RealTimeAlertConfiguration>,
    /// <p>The elements in the request, such as a processor for Amazon Transcribe or a sink for a Kinesis Data Stream..</p>
    pub elements: ::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationElement>>,
}
impl UpdateMediaInsightsPipelineConfigurationInput {
    /// <p>The unique identifier for the resource to be updated. Valid values include the name and ARN of the media insights pipeline configuration.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The ARN of the role used by the service to access Amazon Web Services resources.</p>
    pub fn resource_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.resource_access_role_arn.as_deref()
    }
    /// <p>The configuration settings for real-time alerts for the media insights pipeline.</p>
    pub fn real_time_alert_configuration(&self) -> ::std::option::Option<&crate::types::RealTimeAlertConfiguration> {
        self.real_time_alert_configuration.as_ref()
    }
    /// <p>The elements in the request, such as a processor for Amazon Transcribe or a sink for a Kinesis Data Stream..</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.elements.is_none()`.
    pub fn elements(&self) -> &[crate::types::MediaInsightsPipelineConfigurationElement] {
        self.elements.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for UpdateMediaInsightsPipelineConfigurationInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateMediaInsightsPipelineConfigurationInput");
        formatter.field("identifier", &self.identifier);
        formatter.field("resource_access_role_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("real_time_alert_configuration", &self.real_time_alert_configuration);
        formatter.field("elements", &self.elements);
        formatter.finish()
    }
}
impl UpdateMediaInsightsPipelineConfigurationInput {
    /// Creates a new builder-style object to manufacture [`UpdateMediaInsightsPipelineConfigurationInput`](crate::operation::update_media_insights_pipeline_configuration::UpdateMediaInsightsPipelineConfigurationInput).
    pub fn builder() -> crate::operation::update_media_insights_pipeline_configuration::builders::UpdateMediaInsightsPipelineConfigurationInputBuilder
    {
        crate::operation::update_media_insights_pipeline_configuration::builders::UpdateMediaInsightsPipelineConfigurationInputBuilder::default()
    }
}

/// A builder for [`UpdateMediaInsightsPipelineConfigurationInput`](crate::operation::update_media_insights_pipeline_configuration::UpdateMediaInsightsPipelineConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateMediaInsightsPipelineConfigurationInputBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) resource_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) real_time_alert_configuration: ::std::option::Option<crate::types::RealTimeAlertConfiguration>,
    pub(crate) elements: ::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationElement>>,
}
impl UpdateMediaInsightsPipelineConfigurationInputBuilder {
    /// <p>The unique identifier for the resource to be updated. Valid values include the name and ARN of the media insights pipeline configuration.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the resource to be updated. Valid values include the name and ARN of the media insights pipeline configuration.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The unique identifier for the resource to be updated. Valid values include the name and ARN of the media insights pipeline configuration.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The ARN of the role used by the service to access Amazon Web Services resources.</p>
    /// This field is required.
    pub fn resource_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the role used by the service to access Amazon Web Services resources.</p>
    pub fn set_resource_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_access_role_arn = input;
        self
    }
    /// <p>The ARN of the role used by the service to access Amazon Web Services resources.</p>
    pub fn get_resource_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_access_role_arn
    }
    /// <p>The configuration settings for real-time alerts for the media insights pipeline.</p>
    pub fn real_time_alert_configuration(mut self, input: crate::types::RealTimeAlertConfiguration) -> Self {
        self.real_time_alert_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration settings for real-time alerts for the media insights pipeline.</p>
    pub fn set_real_time_alert_configuration(mut self, input: ::std::option::Option<crate::types::RealTimeAlertConfiguration>) -> Self {
        self.real_time_alert_configuration = input;
        self
    }
    /// <p>The configuration settings for real-time alerts for the media insights pipeline.</p>
    pub fn get_real_time_alert_configuration(&self) -> &::std::option::Option<crate::types::RealTimeAlertConfiguration> {
        &self.real_time_alert_configuration
    }
    /// Appends an item to `elements`.
    ///
    /// To override the contents of this collection use [`set_elements`](Self::set_elements).
    ///
    /// <p>The elements in the request, such as a processor for Amazon Transcribe or a sink for a Kinesis Data Stream..</p>
    pub fn elements(mut self, input: crate::types::MediaInsightsPipelineConfigurationElement) -> Self {
        let mut v = self.elements.unwrap_or_default();
        v.push(input);
        self.elements = ::std::option::Option::Some(v);
        self
    }
    /// <p>The elements in the request, such as a processor for Amazon Transcribe or a sink for a Kinesis Data Stream..</p>
    pub fn set_elements(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationElement>>) -> Self {
        self.elements = input;
        self
    }
    /// <p>The elements in the request, such as a processor for Amazon Transcribe or a sink for a Kinesis Data Stream..</p>
    pub fn get_elements(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MediaInsightsPipelineConfigurationElement>> {
        &self.elements
    }
    /// Consumes the builder and constructs a [`UpdateMediaInsightsPipelineConfigurationInput`](crate::operation::update_media_insights_pipeline_configuration::UpdateMediaInsightsPipelineConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_media_insights_pipeline_configuration::UpdateMediaInsightsPipelineConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_media_insights_pipeline_configuration::UpdateMediaInsightsPipelineConfigurationInput {
                identifier: self.identifier,
                resource_access_role_arn: self.resource_access_role_arn,
                real_time_alert_configuration: self.real_time_alert_configuration,
                elements: self.elements,
            },
        )
    }
}
impl ::std::fmt::Debug for UpdateMediaInsightsPipelineConfigurationInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateMediaInsightsPipelineConfigurationInputBuilder");
        formatter.field("identifier", &self.identifier);
        formatter.field("resource_access_role_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("real_time_alert_configuration", &self.real_time_alert_configuration);
        formatter.field("elements", &self.elements);
        formatter.finish()
    }
}
