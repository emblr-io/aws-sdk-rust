// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The settings for a custom message activity. This type of activity calls an AWS Lambda function or web hook that sends messages to participants.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomMessageActivity {
    /// <p>The destination to send the campaign or treatment to. This value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The name or Amazon Resource Name (ARN) of an AWS Lambda function to invoke to handle delivery of the campaign or treatment.</p></li>
    /// <li>
    /// <p>The URL for a web application or service that supports HTTPS and can receive the message. The URL has to be a full URL, including the HTTPS protocol.</p></li>
    /// </ul>
    pub delivery_uri: ::std::option::Option<::std::string::String>,
    /// <p>The types of endpoints to send the custom message to. Each valid value maps to a type of channel that you can associate with an endpoint by using the ChannelType property of an endpoint.</p>
    pub endpoint_types: ::std::option::Option<::std::vec::Vec<crate::types::EndpointTypesElement>>,
    /// <p>Specifies the message data included in a custom channel message that's sent to participants in a journey.</p>
    pub message_config: ::std::option::Option<crate::types::JourneyCustomMessage>,
    /// <p>The unique identifier for the next activity to perform, after Amazon Pinpoint calls the AWS Lambda function or web hook.</p>
    pub next_activity: ::std::option::Option<::std::string::String>,
    /// <p>The name of the custom message template to use for the message. If specified, this value must match the name of an existing message template.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the version of the message template to use for the message. If specified, this value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If you don't specify a value for this property, Amazon Pinpoint uses the <i>active version</i> of the template. The <i>active version</i> is typically the version of a template that's been most recently reviewed and approved for use, depending on your workflow. It isn't necessarily the latest version of a template.</p>
    pub template_version: ::std::option::Option<::std::string::String>,
}
impl CustomMessageActivity {
    /// <p>The destination to send the campaign or treatment to. This value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The name or Amazon Resource Name (ARN) of an AWS Lambda function to invoke to handle delivery of the campaign or treatment.</p></li>
    /// <li>
    /// <p>The URL for a web application or service that supports HTTPS and can receive the message. The URL has to be a full URL, including the HTTPS protocol.</p></li>
    /// </ul>
    pub fn delivery_uri(&self) -> ::std::option::Option<&str> {
        self.delivery_uri.as_deref()
    }
    /// <p>The types of endpoints to send the custom message to. Each valid value maps to a type of channel that you can associate with an endpoint by using the ChannelType property of an endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.endpoint_types.is_none()`.
    pub fn endpoint_types(&self) -> &[crate::types::EndpointTypesElement] {
        self.endpoint_types.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the message data included in a custom channel message that's sent to participants in a journey.</p>
    pub fn message_config(&self) -> ::std::option::Option<&crate::types::JourneyCustomMessage> {
        self.message_config.as_ref()
    }
    /// <p>The unique identifier for the next activity to perform, after Amazon Pinpoint calls the AWS Lambda function or web hook.</p>
    pub fn next_activity(&self) -> ::std::option::Option<&str> {
        self.next_activity.as_deref()
    }
    /// <p>The name of the custom message template to use for the message. If specified, this value must match the name of an existing message template.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The unique identifier for the version of the message template to use for the message. If specified, this value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If you don't specify a value for this property, Amazon Pinpoint uses the <i>active version</i> of the template. The <i>active version</i> is typically the version of a template that's been most recently reviewed and approved for use, depending on your workflow. It isn't necessarily the latest version of a template.</p>
    pub fn template_version(&self) -> ::std::option::Option<&str> {
        self.template_version.as_deref()
    }
}
impl CustomMessageActivity {
    /// Creates a new builder-style object to manufacture [`CustomMessageActivity`](crate::types::CustomMessageActivity).
    pub fn builder() -> crate::types::builders::CustomMessageActivityBuilder {
        crate::types::builders::CustomMessageActivityBuilder::default()
    }
}

/// A builder for [`CustomMessageActivity`](crate::types::CustomMessageActivity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomMessageActivityBuilder {
    pub(crate) delivery_uri: ::std::option::Option<::std::string::String>,
    pub(crate) endpoint_types: ::std::option::Option<::std::vec::Vec<crate::types::EndpointTypesElement>>,
    pub(crate) message_config: ::std::option::Option<crate::types::JourneyCustomMessage>,
    pub(crate) next_activity: ::std::option::Option<::std::string::String>,
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) template_version: ::std::option::Option<::std::string::String>,
}
impl CustomMessageActivityBuilder {
    /// <p>The destination to send the campaign or treatment to. This value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The name or Amazon Resource Name (ARN) of an AWS Lambda function to invoke to handle delivery of the campaign or treatment.</p></li>
    /// <li>
    /// <p>The URL for a web application or service that supports HTTPS and can receive the message. The URL has to be a full URL, including the HTTPS protocol.</p></li>
    /// </ul>
    pub fn delivery_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The destination to send the campaign or treatment to. This value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The name or Amazon Resource Name (ARN) of an AWS Lambda function to invoke to handle delivery of the campaign or treatment.</p></li>
    /// <li>
    /// <p>The URL for a web application or service that supports HTTPS and can receive the message. The URL has to be a full URL, including the HTTPS protocol.</p></li>
    /// </ul>
    pub fn set_delivery_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_uri = input;
        self
    }
    /// <p>The destination to send the campaign or treatment to. This value can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>The name or Amazon Resource Name (ARN) of an AWS Lambda function to invoke to handle delivery of the campaign or treatment.</p></li>
    /// <li>
    /// <p>The URL for a web application or service that supports HTTPS and can receive the message. The URL has to be a full URL, including the HTTPS protocol.</p></li>
    /// </ul>
    pub fn get_delivery_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_uri
    }
    /// Appends an item to `endpoint_types`.
    ///
    /// To override the contents of this collection use [`set_endpoint_types`](Self::set_endpoint_types).
    ///
    /// <p>The types of endpoints to send the custom message to. Each valid value maps to a type of channel that you can associate with an endpoint by using the ChannelType property of an endpoint.</p>
    pub fn endpoint_types(mut self, input: crate::types::EndpointTypesElement) -> Self {
        let mut v = self.endpoint_types.unwrap_or_default();
        v.push(input);
        self.endpoint_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types of endpoints to send the custom message to. Each valid value maps to a type of channel that you can associate with an endpoint by using the ChannelType property of an endpoint.</p>
    pub fn set_endpoint_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EndpointTypesElement>>) -> Self {
        self.endpoint_types = input;
        self
    }
    /// <p>The types of endpoints to send the custom message to. Each valid value maps to a type of channel that you can associate with an endpoint by using the ChannelType property of an endpoint.</p>
    pub fn get_endpoint_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EndpointTypesElement>> {
        &self.endpoint_types
    }
    /// <p>Specifies the message data included in a custom channel message that's sent to participants in a journey.</p>
    pub fn message_config(mut self, input: crate::types::JourneyCustomMessage) -> Self {
        self.message_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the message data included in a custom channel message that's sent to participants in a journey.</p>
    pub fn set_message_config(mut self, input: ::std::option::Option<crate::types::JourneyCustomMessage>) -> Self {
        self.message_config = input;
        self
    }
    /// <p>Specifies the message data included in a custom channel message that's sent to participants in a journey.</p>
    pub fn get_message_config(&self) -> &::std::option::Option<crate::types::JourneyCustomMessage> {
        &self.message_config
    }
    /// <p>The unique identifier for the next activity to perform, after Amazon Pinpoint calls the AWS Lambda function or web hook.</p>
    pub fn next_activity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_activity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the next activity to perform, after Amazon Pinpoint calls the AWS Lambda function or web hook.</p>
    pub fn set_next_activity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_activity = input;
        self
    }
    /// <p>The unique identifier for the next activity to perform, after Amazon Pinpoint calls the AWS Lambda function or web hook.</p>
    pub fn get_next_activity(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_activity
    }
    /// <p>The name of the custom message template to use for the message. If specified, this value must match the name of an existing message template.</p>
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the custom message template to use for the message. If specified, this value must match the name of an existing message template.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the custom message template to use for the message. If specified, this value must match the name of an existing message template.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The unique identifier for the version of the message template to use for the message. If specified, this value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If you don't specify a value for this property, Amazon Pinpoint uses the <i>active version</i> of the template. The <i>active version</i> is typically the version of a template that's been most recently reviewed and approved for use, depending on your workflow. It isn't necessarily the latest version of a template.</p>
    pub fn template_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the version of the message template to use for the message. If specified, this value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If you don't specify a value for this property, Amazon Pinpoint uses the <i>active version</i> of the template. The <i>active version</i> is typically the version of a template that's been most recently reviewed and approved for use, depending on your workflow. It isn't necessarily the latest version of a template.</p>
    pub fn set_template_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_version = input;
        self
    }
    /// <p>The unique identifier for the version of the message template to use for the message. If specified, this value must match the identifier for an existing template version. To retrieve a list of versions and version identifiers for a template, use the
    /// <link linkend="templates-template-name-template-type-versions">Template Versions resource.</p>
    /// <p>If you don't specify a value for this property, Amazon Pinpoint uses the <i>active version</i> of the template. The <i>active version</i> is typically the version of a template that's been most recently reviewed and approved for use, depending on your workflow. It isn't necessarily the latest version of a template.</p>
    pub fn get_template_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_version
    }
    /// Consumes the builder and constructs a [`CustomMessageActivity`](crate::types::CustomMessageActivity).
    pub fn build(self) -> crate::types::CustomMessageActivity {
        crate::types::CustomMessageActivity {
            delivery_uri: self.delivery_uri,
            endpoint_types: self.endpoint_types,
            message_config: self.message_config,
            next_activity: self.next_activity,
            template_name: self.template_name,
            template_version: self.template_version,
        }
    }
}
