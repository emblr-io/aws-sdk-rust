// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A behavior assessment of a topic policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GuardrailTopicPolicyAssessment {
    /// <p>The topics in the assessment.</p>
    pub topics: ::std::vec::Vec<crate::types::GuardrailTopic>,
}
impl GuardrailTopicPolicyAssessment {
    /// <p>The topics in the assessment.</p>
    pub fn topics(&self) -> &[crate::types::GuardrailTopic] {
        use std::ops::Deref;
        self.topics.deref()
    }
}
impl GuardrailTopicPolicyAssessment {
    /// Creates a new builder-style object to manufacture [`GuardrailTopicPolicyAssessment`](crate::types::GuardrailTopicPolicyAssessment).
    pub fn builder() -> crate::types::builders::GuardrailTopicPolicyAssessmentBuilder {
        crate::types::builders::GuardrailTopicPolicyAssessmentBuilder::default()
    }
}

/// A builder for [`GuardrailTopicPolicyAssessment`](crate::types::GuardrailTopicPolicyAssessment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GuardrailTopicPolicyAssessmentBuilder {
    pub(crate) topics: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailTopic>>,
}
impl GuardrailTopicPolicyAssessmentBuilder {
    /// Appends an item to `topics`.
    ///
    /// To override the contents of this collection use [`set_topics`](Self::set_topics).
    ///
    /// <p>The topics in the assessment.</p>
    pub fn topics(mut self, input: crate::types::GuardrailTopic) -> Self {
        let mut v = self.topics.unwrap_or_default();
        v.push(input);
        self.topics = ::std::option::Option::Some(v);
        self
    }
    /// <p>The topics in the assessment.</p>
    pub fn set_topics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailTopic>>) -> Self {
        self.topics = input;
        self
    }
    /// <p>The topics in the assessment.</p>
    pub fn get_topics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailTopic>> {
        &self.topics
    }
    /// Consumes the builder and constructs a [`GuardrailTopicPolicyAssessment`](crate::types::GuardrailTopicPolicyAssessment).
    /// This method will fail if any of the following fields are not set:
    /// - [`topics`](crate::types::builders::GuardrailTopicPolicyAssessmentBuilder::topics)
    pub fn build(self) -> ::std::result::Result<crate::types::GuardrailTopicPolicyAssessment, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GuardrailTopicPolicyAssessment {
            topics: self.topics.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "topics",
                    "topics was not specified but it is required when building GuardrailTopicPolicyAssessment",
                )
            })?,
        })
    }
}
