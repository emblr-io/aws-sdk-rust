// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A high-level overview of a voice profile domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct VoiceProfileDomainSummary {
    /// <p>The ID of the voice profile domain summary.</p>
    pub voice_profile_domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of a voice profile in a voice profile domain summary.</p>
    pub voice_profile_domain_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the voice profile domain summary.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Describes the voice profile domain summary.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the voice profile domain summary was created.</p>
    pub created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time at which the voice profile domain summary was last updated.</p>
    pub updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl VoiceProfileDomainSummary {
    /// <p>The ID of the voice profile domain summary.</p>
    pub fn voice_profile_domain_id(&self) -> ::std::option::Option<&str> {
        self.voice_profile_domain_id.as_deref()
    }
    /// <p>The ARN of a voice profile in a voice profile domain summary.</p>
    pub fn voice_profile_domain_arn(&self) -> ::std::option::Option<&str> {
        self.voice_profile_domain_arn.as_deref()
    }
    /// <p>The name of the voice profile domain summary.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Describes the voice profile domain summary.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The time at which the voice profile domain summary was created.</p>
    pub fn created_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_timestamp.as_ref()
    }
    /// <p>The time at which the voice profile domain summary was last updated.</p>
    pub fn updated_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_timestamp.as_ref()
    }
}
impl ::std::fmt::Debug for VoiceProfileDomainSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VoiceProfileDomainSummary");
        formatter.field("voice_profile_domain_id", &self.voice_profile_domain_id);
        formatter.field("voice_profile_domain_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("created_timestamp", &self.created_timestamp);
        formatter.field("updated_timestamp", &self.updated_timestamp);
        formatter.finish()
    }
}
impl VoiceProfileDomainSummary {
    /// Creates a new builder-style object to manufacture [`VoiceProfileDomainSummary`](crate::types::VoiceProfileDomainSummary).
    pub fn builder() -> crate::types::builders::VoiceProfileDomainSummaryBuilder {
        crate::types::builders::VoiceProfileDomainSummaryBuilder::default()
    }
}

/// A builder for [`VoiceProfileDomainSummary`](crate::types::VoiceProfileDomainSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct VoiceProfileDomainSummaryBuilder {
    pub(crate) voice_profile_domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) voice_profile_domain_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) created_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl VoiceProfileDomainSummaryBuilder {
    /// <p>The ID of the voice profile domain summary.</p>
    pub fn voice_profile_domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.voice_profile_domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the voice profile domain summary.</p>
    pub fn set_voice_profile_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.voice_profile_domain_id = input;
        self
    }
    /// <p>The ID of the voice profile domain summary.</p>
    pub fn get_voice_profile_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.voice_profile_domain_id
    }
    /// <p>The ARN of a voice profile in a voice profile domain summary.</p>
    pub fn voice_profile_domain_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.voice_profile_domain_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of a voice profile in a voice profile domain summary.</p>
    pub fn set_voice_profile_domain_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.voice_profile_domain_arn = input;
        self
    }
    /// <p>The ARN of a voice profile in a voice profile domain summary.</p>
    pub fn get_voice_profile_domain_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.voice_profile_domain_arn
    }
    /// <p>The name of the voice profile domain summary.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the voice profile domain summary.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the voice profile domain summary.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Describes the voice profile domain summary.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Describes the voice profile domain summary.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Describes the voice profile domain summary.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The time at which the voice profile domain summary was created.</p>
    pub fn created_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the voice profile domain summary was created.</p>
    pub fn set_created_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_timestamp = input;
        self
    }
    /// <p>The time at which the voice profile domain summary was created.</p>
    pub fn get_created_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_timestamp
    }
    /// <p>The time at which the voice profile domain summary was last updated.</p>
    pub fn updated_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the voice profile domain summary was last updated.</p>
    pub fn set_updated_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_timestamp = input;
        self
    }
    /// <p>The time at which the voice profile domain summary was last updated.</p>
    pub fn get_updated_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_timestamp
    }
    /// Consumes the builder and constructs a [`VoiceProfileDomainSummary`](crate::types::VoiceProfileDomainSummary).
    pub fn build(self) -> crate::types::VoiceProfileDomainSummary {
        crate::types::VoiceProfileDomainSummary {
            voice_profile_domain_id: self.voice_profile_domain_id,
            voice_profile_domain_arn: self.voice_profile_domain_arn,
            name: self.name,
            description: self.description,
            created_timestamp: self.created_timestamp,
            updated_timestamp: self.updated_timestamp,
        }
    }
}
impl ::std::fmt::Debug for VoiceProfileDomainSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VoiceProfileDomainSummaryBuilder");
        formatter.field("voice_profile_domain_id", &self.voice_profile_domain_id);
        formatter.field("voice_profile_domain_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("created_timestamp", &self.created_timestamp);
        formatter.field("updated_timestamp", &self.updated_timestamp);
        formatter.finish()
    }
}
