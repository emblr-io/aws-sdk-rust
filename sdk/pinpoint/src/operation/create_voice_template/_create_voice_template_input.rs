// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateVoiceTemplateInput {
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the content and settings for a message template that can be used in messages that are sent through the voice channel.</p>
    pub voice_template_request: ::std::option::Option<crate::types::VoiceTemplateRequest>,
}
impl CreateVoiceTemplateInput {
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>Specifies the content and settings for a message template that can be used in messages that are sent through the voice channel.</p>
    pub fn voice_template_request(&self) -> ::std::option::Option<&crate::types::VoiceTemplateRequest> {
        self.voice_template_request.as_ref()
    }
}
impl CreateVoiceTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateVoiceTemplateInput`](crate::operation::create_voice_template::CreateVoiceTemplateInput).
    pub fn builder() -> crate::operation::create_voice_template::builders::CreateVoiceTemplateInputBuilder {
        crate::operation::create_voice_template::builders::CreateVoiceTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateVoiceTemplateInput`](crate::operation::create_voice_template::CreateVoiceTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateVoiceTemplateInputBuilder {
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) voice_template_request: ::std::option::Option<crate::types::VoiceTemplateRequest>,
}
impl CreateVoiceTemplateInputBuilder {
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the message template. A template name must start with an alphanumeric character and can contain a maximum of 128 characters. The characters can be alphanumeric characters, underscores (_), or hyphens (-). Template names are case sensitive.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>Specifies the content and settings for a message template that can be used in messages that are sent through the voice channel.</p>
    /// This field is required.
    pub fn voice_template_request(mut self, input: crate::types::VoiceTemplateRequest) -> Self {
        self.voice_template_request = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the content and settings for a message template that can be used in messages that are sent through the voice channel.</p>
    pub fn set_voice_template_request(mut self, input: ::std::option::Option<crate::types::VoiceTemplateRequest>) -> Self {
        self.voice_template_request = input;
        self
    }
    /// <p>Specifies the content and settings for a message template that can be used in messages that are sent through the voice channel.</p>
    pub fn get_voice_template_request(&self) -> &::std::option::Option<crate::types::VoiceTemplateRequest> {
        &self.voice_template_request
    }
    /// Consumes the builder and constructs a [`CreateVoiceTemplateInput`](crate::operation::create_voice_template::CreateVoiceTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_voice_template::CreateVoiceTemplateInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_voice_template::CreateVoiceTemplateInput {
            template_name: self.template_name,
            voice_template_request: self.voice_template_request,
        })
    }
}
