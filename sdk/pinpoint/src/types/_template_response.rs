// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a message template that's associated with your Amazon Pinpoint account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TemplateResponse {
    /// <p>The Amazon Resource Name (ARN) of the message template. This value isn't included in a TemplateResponse object. To retrieve the ARN of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the ARN for.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The date, in ISO 8601 format, when the message template was created.</p>
    pub creation_date: ::std::option::Option<::std::string::String>,
    /// <p>The JSON object that specifies the default values that are used for message variables in the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub default_substitutions: ::std::option::Option<::std::string::String>,
    /// <p>The date, in ISO 8601 format, when the message template was last modified.</p>
    pub last_modified_date: ::std::option::Option<::std::string::String>,
    /// <p>A map of key-value pairs that identifies the tags that are associated with the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The custom description of the message template. This value isn't included in a TemplateResponse object. To retrieve the description of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the description for.</p>
    pub template_description: ::std::option::Option<::std::string::String>,
    /// <p>The name of the message template.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of channel that the message template is designed for. Possible values are: EMAIL, PUSH, SMS, INAPP, and VOICE.</p>
    pub template_type: ::std::option::Option<crate::types::TemplateType>,
    /// <p>The unique identifier, as an integer, for the active version of the message template.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl TemplateResponse {
    /// <p>The Amazon Resource Name (ARN) of the message template. This value isn't included in a TemplateResponse object. To retrieve the ARN of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the ARN for.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The date, in ISO 8601 format, when the message template was created.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&str> {
        self.creation_date.as_deref()
    }
    /// <p>The JSON object that specifies the default values that are used for message variables in the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn default_substitutions(&self) -> ::std::option::Option<&str> {
        self.default_substitutions.as_deref()
    }
    /// <p>The date, in ISO 8601 format, when the message template was last modified.</p>
    pub fn last_modified_date(&self) -> ::std::option::Option<&str> {
        self.last_modified_date.as_deref()
    }
    /// <p>A map of key-value pairs that identifies the tags that are associated with the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The custom description of the message template. This value isn't included in a TemplateResponse object. To retrieve the description of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the description for.</p>
    pub fn template_description(&self) -> ::std::option::Option<&str> {
        self.template_description.as_deref()
    }
    /// <p>The name of the message template.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The type of channel that the message template is designed for. Possible values are: EMAIL, PUSH, SMS, INAPP, and VOICE.</p>
    pub fn template_type(&self) -> ::std::option::Option<&crate::types::TemplateType> {
        self.template_type.as_ref()
    }
    /// <p>The unique identifier, as an integer, for the active version of the message template.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl TemplateResponse {
    /// Creates a new builder-style object to manufacture [`TemplateResponse`](crate::types::TemplateResponse).
    pub fn builder() -> crate::types::builders::TemplateResponseBuilder {
        crate::types::builders::TemplateResponseBuilder::default()
    }
}

/// A builder for [`TemplateResponse`](crate::types::TemplateResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TemplateResponseBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::std::string::String>,
    pub(crate) default_substitutions: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_date: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) template_description: ::std::option::Option<::std::string::String>,
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) template_type: ::std::option::Option<crate::types::TemplateType>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl TemplateResponseBuilder {
    /// <p>The Amazon Resource Name (ARN) of the message template. This value isn't included in a TemplateResponse object. To retrieve the ARN of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the ARN for.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the message template. This value isn't included in a TemplateResponse object. To retrieve the ARN of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the ARN for.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the message template. This value isn't included in a TemplateResponse object. To retrieve the ARN of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the ARN for.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The date, in ISO 8601 format, when the message template was created.</p>
    /// This field is required.
    pub fn creation_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creation_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date, in ISO 8601 format, when the message template was created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date, in ISO 8601 format, when the message template was created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.creation_date
    }
    /// <p>The JSON object that specifies the default values that are used for message variables in the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn default_substitutions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_substitutions = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON object that specifies the default values that are used for message variables in the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn set_default_substitutions(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_substitutions = input;
        self
    }
    /// <p>The JSON object that specifies the default values that are used for message variables in the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn get_default_substitutions(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_substitutions
    }
    /// <p>The date, in ISO 8601 format, when the message template was last modified.</p>
    /// This field is required.
    pub fn last_modified_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date, in ISO 8601 format, when the message template was last modified.</p>
    pub fn set_last_modified_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_date = input;
        self
    }
    /// <p>The date, in ISO 8601 format, when the message template was last modified.</p>
    pub fn get_last_modified_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_date
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map of key-value pairs that identifies the tags that are associated with the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of key-value pairs that identifies the tags that are associated with the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map of key-value pairs that identifies the tags that are associated with the message template. This object isn't included in a TemplateResponse object. To retrieve this object for a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the object for.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The custom description of the message template. This value isn't included in a TemplateResponse object. To retrieve the description of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the description for.</p>
    pub fn template_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom description of the message template. This value isn't included in a TemplateResponse object. To retrieve the description of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the description for.</p>
    pub fn set_template_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_description = input;
        self
    }
    /// <p>The custom description of the message template. This value isn't included in a TemplateResponse object. To retrieve the description of a template, use the GetEmailTemplate, GetPushTemplate, GetSmsTemplate, or GetVoiceTemplate operation, depending on the type of template that you want to retrieve the description for.</p>
    pub fn get_template_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_description
    }
    /// <p>The name of the message template.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the message template.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the message template.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The type of channel that the message template is designed for. Possible values are: EMAIL, PUSH, SMS, INAPP, and VOICE.</p>
    /// This field is required.
    pub fn template_type(mut self, input: crate::types::TemplateType) -> Self {
        self.template_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of channel that the message template is designed for. Possible values are: EMAIL, PUSH, SMS, INAPP, and VOICE.</p>
    pub fn set_template_type(mut self, input: ::std::option::Option<crate::types::TemplateType>) -> Self {
        self.template_type = input;
        self
    }
    /// <p>The type of channel that the message template is designed for. Possible values are: EMAIL, PUSH, SMS, INAPP, and VOICE.</p>
    pub fn get_template_type(&self) -> &::std::option::Option<crate::types::TemplateType> {
        &self.template_type
    }
    /// <p>The unique identifier, as an integer, for the active version of the message template.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier, as an integer, for the active version of the message template.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The unique identifier, as an integer, for the active version of the message template.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`TemplateResponse`](crate::types::TemplateResponse).
    pub fn build(self) -> crate::types::TemplateResponse {
        crate::types::TemplateResponse {
            arn: self.arn,
            creation_date: self.creation_date,
            default_substitutions: self.default_substitutions,
            last_modified_date: self.last_modified_date,
            tags: self.tags,
            template_description: self.template_description,
            template_name: self.template_name,
            template_type: self.template_type,
            version: self.version,
        }
    }
}
