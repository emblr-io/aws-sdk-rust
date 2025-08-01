// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration options for a <code>Topic</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TopicConfigOptions {
    /// <p>Enables Amazon Q Business Insights for a <code>Topic</code>.</p>
    pub q_business_insights_enabled: ::std::option::Option<bool>,
}
impl TopicConfigOptions {
    /// <p>Enables Amazon Q Business Insights for a <code>Topic</code>.</p>
    pub fn q_business_insights_enabled(&self) -> ::std::option::Option<bool> {
        self.q_business_insights_enabled
    }
}
impl TopicConfigOptions {
    /// Creates a new builder-style object to manufacture [`TopicConfigOptions`](crate::types::TopicConfigOptions).
    pub fn builder() -> crate::types::builders::TopicConfigOptionsBuilder {
        crate::types::builders::TopicConfigOptionsBuilder::default()
    }
}

/// A builder for [`TopicConfigOptions`](crate::types::TopicConfigOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TopicConfigOptionsBuilder {
    pub(crate) q_business_insights_enabled: ::std::option::Option<bool>,
}
impl TopicConfigOptionsBuilder {
    /// <p>Enables Amazon Q Business Insights for a <code>Topic</code>.</p>
    pub fn q_business_insights_enabled(mut self, input: bool) -> Self {
        self.q_business_insights_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables Amazon Q Business Insights for a <code>Topic</code>.</p>
    pub fn set_q_business_insights_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.q_business_insights_enabled = input;
        self
    }
    /// <p>Enables Amazon Q Business Insights for a <code>Topic</code>.</p>
    pub fn get_q_business_insights_enabled(&self) -> &::std::option::Option<bool> {
        &self.q_business_insights_enabled
    }
    /// Consumes the builder and constructs a [`TopicConfigOptions`](crate::types::TopicConfigOptions).
    pub fn build(self) -> crate::types::TopicConfigOptions {
        crate::types::TopicConfigOptions {
            q_business_insights_enabled: self.q_business_insights_enabled,
        }
    }
}
