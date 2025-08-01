// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A topic summary.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TopicSummary {
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the topic. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub topic_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the topic.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The user experience version of the topic.</p>
    pub user_experience_version: ::std::option::Option<crate::types::TopicUserExperienceVersion>,
}
impl TopicSummary {
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ID for the topic. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(&self) -> ::std::option::Option<&str> {
        self.topic_id.as_deref()
    }
    /// <p>The name of the topic.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The user experience version of the topic.</p>
    pub fn user_experience_version(&self) -> ::std::option::Option<&crate::types::TopicUserExperienceVersion> {
        self.user_experience_version.as_ref()
    }
}
impl TopicSummary {
    /// Creates a new builder-style object to manufacture [`TopicSummary`](crate::types::TopicSummary).
    pub fn builder() -> crate::types::builders::TopicSummaryBuilder {
        crate::types::builders::TopicSummaryBuilder::default()
    }
}

/// A builder for [`TopicSummary`](crate::types::TopicSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TopicSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) topic_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) user_experience_version: ::std::option::Option<crate::types::TopicUserExperienceVersion>,
}
impl TopicSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the topic.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ID for the topic. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn topic_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the topic. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn set_topic_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_id = input;
        self
    }
    /// <p>The ID for the topic. This ID is unique per Amazon Web Services Region for each Amazon Web Services account.</p>
    pub fn get_topic_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_id
    }
    /// <p>The name of the topic.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the topic.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the topic.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The user experience version of the topic.</p>
    pub fn user_experience_version(mut self, input: crate::types::TopicUserExperienceVersion) -> Self {
        self.user_experience_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user experience version of the topic.</p>
    pub fn set_user_experience_version(mut self, input: ::std::option::Option<crate::types::TopicUserExperienceVersion>) -> Self {
        self.user_experience_version = input;
        self
    }
    /// <p>The user experience version of the topic.</p>
    pub fn get_user_experience_version(&self) -> &::std::option::Option<crate::types::TopicUserExperienceVersion> {
        &self.user_experience_version
    }
    /// Consumes the builder and constructs a [`TopicSummary`](crate::types::TopicSummary).
    pub fn build(self) -> crate::types::TopicSummary {
        crate::types::TopicSummary {
            arn: self.arn,
            topic_id: self.topic_id,
            name: self.name,
            user_experience_version: self.user_experience_version,
        }
    }
}
