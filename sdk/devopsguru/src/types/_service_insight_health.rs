// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the number of open proactive and reactive insights in an analyzed Amazon Web Services service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceInsightHealth {
    /// <p>The number of open proactive insights in the Amazon Web Services service</p>
    pub open_proactive_insights: i32,
    /// <p>The number of open reactive insights in the Amazon Web Services service</p>
    pub open_reactive_insights: i32,
}
impl ServiceInsightHealth {
    /// <p>The number of open proactive insights in the Amazon Web Services service</p>
    pub fn open_proactive_insights(&self) -> i32 {
        self.open_proactive_insights
    }
    /// <p>The number of open reactive insights in the Amazon Web Services service</p>
    pub fn open_reactive_insights(&self) -> i32 {
        self.open_reactive_insights
    }
}
impl ServiceInsightHealth {
    /// Creates a new builder-style object to manufacture [`ServiceInsightHealth`](crate::types::ServiceInsightHealth).
    pub fn builder() -> crate::types::builders::ServiceInsightHealthBuilder {
        crate::types::builders::ServiceInsightHealthBuilder::default()
    }
}

/// A builder for [`ServiceInsightHealth`](crate::types::ServiceInsightHealth).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceInsightHealthBuilder {
    pub(crate) open_proactive_insights: ::std::option::Option<i32>,
    pub(crate) open_reactive_insights: ::std::option::Option<i32>,
}
impl ServiceInsightHealthBuilder {
    /// <p>The number of open proactive insights in the Amazon Web Services service</p>
    pub fn open_proactive_insights(mut self, input: i32) -> Self {
        self.open_proactive_insights = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of open proactive insights in the Amazon Web Services service</p>
    pub fn set_open_proactive_insights(mut self, input: ::std::option::Option<i32>) -> Self {
        self.open_proactive_insights = input;
        self
    }
    /// <p>The number of open proactive insights in the Amazon Web Services service</p>
    pub fn get_open_proactive_insights(&self) -> &::std::option::Option<i32> {
        &self.open_proactive_insights
    }
    /// <p>The number of open reactive insights in the Amazon Web Services service</p>
    pub fn open_reactive_insights(mut self, input: i32) -> Self {
        self.open_reactive_insights = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of open reactive insights in the Amazon Web Services service</p>
    pub fn set_open_reactive_insights(mut self, input: ::std::option::Option<i32>) -> Self {
        self.open_reactive_insights = input;
        self
    }
    /// <p>The number of open reactive insights in the Amazon Web Services service</p>
    pub fn get_open_reactive_insights(&self) -> &::std::option::Option<i32> {
        &self.open_reactive_insights
    }
    /// Consumes the builder and constructs a [`ServiceInsightHealth`](crate::types::ServiceInsightHealth).
    pub fn build(self) -> crate::types::ServiceInsightHealth {
        crate::types::ServiceInsightHealth {
            open_proactive_insights: self.open_proactive_insights.unwrap_or_default(),
            open_reactive_insights: self.open_reactive_insights.unwrap_or_default(),
        }
    }
}
