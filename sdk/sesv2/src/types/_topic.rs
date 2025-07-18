// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An interest group, theme, or label within a list. Lists can have multiple topics.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Topic {
    /// <p>The name of the topic.</p>
    pub topic_name: ::std::string::String,
    /// <p>The name of the topic the contact will see.</p>
    pub display_name: ::std::string::String,
    /// <p>A description of what the topic is about, which the contact will see.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The default subscription status to be applied to a contact if the contact has not noted their preference for subscribing to a topic.</p>
    pub default_subscription_status: crate::types::SubscriptionStatus,
}
impl Topic {
    /// <p>The name of the topic.</p>
    pub fn topic_name(&self) -> &str {
        use std::ops::Deref;
        self.topic_name.deref()
    }
    /// <p>The name of the topic the contact will see.</p>
    pub fn display_name(&self) -> &str {
        use std::ops::Deref;
        self.display_name.deref()
    }
    /// <p>A description of what the topic is about, which the contact will see.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The default subscription status to be applied to a contact if the contact has not noted their preference for subscribing to a topic.</p>
    pub fn default_subscription_status(&self) -> &crate::types::SubscriptionStatus {
        &self.default_subscription_status
    }
}
impl Topic {
    /// Creates a new builder-style object to manufacture [`Topic`](crate::types::Topic).
    pub fn builder() -> crate::types::builders::TopicBuilder {
        crate::types::builders::TopicBuilder::default()
    }
}

/// A builder for [`Topic`](crate::types::Topic).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TopicBuilder {
    pub(crate) topic_name: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) default_subscription_status: ::std::option::Option<crate::types::SubscriptionStatus>,
}
impl TopicBuilder {
    /// <p>The name of the topic.</p>
    /// This field is required.
    pub fn topic_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the topic.</p>
    pub fn set_topic_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_name = input;
        self
    }
    /// <p>The name of the topic.</p>
    pub fn get_topic_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_name
    }
    /// <p>The name of the topic the contact will see.</p>
    /// This field is required.
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the topic the contact will see.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The name of the topic the contact will see.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>A description of what the topic is about, which the contact will see.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of what the topic is about, which the contact will see.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of what the topic is about, which the contact will see.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The default subscription status to be applied to a contact if the contact has not noted their preference for subscribing to a topic.</p>
    /// This field is required.
    pub fn default_subscription_status(mut self, input: crate::types::SubscriptionStatus) -> Self {
        self.default_subscription_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default subscription status to be applied to a contact if the contact has not noted their preference for subscribing to a topic.</p>
    pub fn set_default_subscription_status(mut self, input: ::std::option::Option<crate::types::SubscriptionStatus>) -> Self {
        self.default_subscription_status = input;
        self
    }
    /// <p>The default subscription status to be applied to a contact if the contact has not noted their preference for subscribing to a topic.</p>
    pub fn get_default_subscription_status(&self) -> &::std::option::Option<crate::types::SubscriptionStatus> {
        &self.default_subscription_status
    }
    /// Consumes the builder and constructs a [`Topic`](crate::types::Topic).
    /// This method will fail if any of the following fields are not set:
    /// - [`topic_name`](crate::types::builders::TopicBuilder::topic_name)
    /// - [`display_name`](crate::types::builders::TopicBuilder::display_name)
    /// - [`default_subscription_status`](crate::types::builders::TopicBuilder::default_subscription_status)
    pub fn build(self) -> ::std::result::Result<crate::types::Topic, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Topic {
            topic_name: self.topic_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "topic_name",
                    "topic_name was not specified but it is required when building Topic",
                )
            })?,
            display_name: self.display_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "display_name",
                    "display_name was not specified but it is required when building Topic",
                )
            })?,
            description: self.description,
            default_subscription_status: self.default_subscription_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "default_subscription_status",
                    "default_subscription_status was not specified but it is required when building Topic",
                )
            })?,
        })
    }
}
