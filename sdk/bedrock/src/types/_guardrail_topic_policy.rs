// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about topics that the guardrail should identify and deny.</p>
/// <p>This data type is used in the following API operations:</p>
/// <ul>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GetGuardrail.html#API_GetGuardrail_ResponseSyntax">GetGuardrail response body</a></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GuardrailTopicPolicy {
    /// <p>A list of policies related to topics that the guardrail should deny.</p>
    pub topics: ::std::vec::Vec<crate::types::GuardrailTopic>,
    /// <p>The tier that your guardrail uses for denied topic filters.</p>
    pub tier: ::std::option::Option<crate::types::GuardrailTopicsTier>,
}
impl GuardrailTopicPolicy {
    /// <p>A list of policies related to topics that the guardrail should deny.</p>
    pub fn topics(&self) -> &[crate::types::GuardrailTopic] {
        use std::ops::Deref;
        self.topics.deref()
    }
    /// <p>The tier that your guardrail uses for denied topic filters.</p>
    pub fn tier(&self) -> ::std::option::Option<&crate::types::GuardrailTopicsTier> {
        self.tier.as_ref()
    }
}
impl GuardrailTopicPolicy {
    /// Creates a new builder-style object to manufacture [`GuardrailTopicPolicy`](crate::types::GuardrailTopicPolicy).
    pub fn builder() -> crate::types::builders::GuardrailTopicPolicyBuilder {
        crate::types::builders::GuardrailTopicPolicyBuilder::default()
    }
}

/// A builder for [`GuardrailTopicPolicy`](crate::types::GuardrailTopicPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GuardrailTopicPolicyBuilder {
    pub(crate) topics: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailTopic>>,
    pub(crate) tier: ::std::option::Option<crate::types::GuardrailTopicsTier>,
}
impl GuardrailTopicPolicyBuilder {
    /// Appends an item to `topics`.
    ///
    /// To override the contents of this collection use [`set_topics`](Self::set_topics).
    ///
    /// <p>A list of policies related to topics that the guardrail should deny.</p>
    pub fn topics(mut self, input: crate::types::GuardrailTopic) -> Self {
        let mut v = self.topics.unwrap_or_default();
        v.push(input);
        self.topics = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of policies related to topics that the guardrail should deny.</p>
    pub fn set_topics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailTopic>>) -> Self {
        self.topics = input;
        self
    }
    /// <p>A list of policies related to topics that the guardrail should deny.</p>
    pub fn get_topics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailTopic>> {
        &self.topics
    }
    /// <p>The tier that your guardrail uses for denied topic filters.</p>
    pub fn tier(mut self, input: crate::types::GuardrailTopicsTier) -> Self {
        self.tier = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tier that your guardrail uses for denied topic filters.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<crate::types::GuardrailTopicsTier>) -> Self {
        self.tier = input;
        self
    }
    /// <p>The tier that your guardrail uses for denied topic filters.</p>
    pub fn get_tier(&self) -> &::std::option::Option<crate::types::GuardrailTopicsTier> {
        &self.tier
    }
    /// Consumes the builder and constructs a [`GuardrailTopicPolicy`](crate::types::GuardrailTopicPolicy).
    /// This method will fail if any of the following fields are not set:
    /// - [`topics`](crate::types::builders::GuardrailTopicPolicyBuilder::topics)
    pub fn build(self) -> ::std::result::Result<crate::types::GuardrailTopicPolicy, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GuardrailTopicPolicy {
            topics: self.topics.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "topics",
                    "topics was not specified but it is required when building GuardrailTopicPolicy",
                )
            })?,
            tier: self.tier,
        })
    }
}
