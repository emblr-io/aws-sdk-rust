// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TestMetricFilterInput {
    /// <p>A symbolic description of how CloudWatch Logs should interpret the data in each log event. For example, a log event can contain timestamps, IP addresses, strings, and so on. You use the filter pattern to specify what to look for in the log event message.</p>
    pub filter_pattern: ::std::option::Option<::std::string::String>,
    /// <p>The log event messages to test.</p>
    pub log_event_messages: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TestMetricFilterInput {
    /// <p>A symbolic description of how CloudWatch Logs should interpret the data in each log event. For example, a log event can contain timestamps, IP addresses, strings, and so on. You use the filter pattern to specify what to look for in the log event message.</p>
    pub fn filter_pattern(&self) -> ::std::option::Option<&str> {
        self.filter_pattern.as_deref()
    }
    /// <p>The log event messages to test.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_event_messages.is_none()`.
    pub fn log_event_messages(&self) -> &[::std::string::String] {
        self.log_event_messages.as_deref().unwrap_or_default()
    }
}
impl TestMetricFilterInput {
    /// Creates a new builder-style object to manufacture [`TestMetricFilterInput`](crate::operation::test_metric_filter::TestMetricFilterInput).
    pub fn builder() -> crate::operation::test_metric_filter::builders::TestMetricFilterInputBuilder {
        crate::operation::test_metric_filter::builders::TestMetricFilterInputBuilder::default()
    }
}

/// A builder for [`TestMetricFilterInput`](crate::operation::test_metric_filter::TestMetricFilterInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TestMetricFilterInputBuilder {
    pub(crate) filter_pattern: ::std::option::Option<::std::string::String>,
    pub(crate) log_event_messages: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl TestMetricFilterInputBuilder {
    /// <p>A symbolic description of how CloudWatch Logs should interpret the data in each log event. For example, a log event can contain timestamps, IP addresses, strings, and so on. You use the filter pattern to specify what to look for in the log event message.</p>
    /// This field is required.
    pub fn filter_pattern(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_pattern = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A symbolic description of how CloudWatch Logs should interpret the data in each log event. For example, a log event can contain timestamps, IP addresses, strings, and so on. You use the filter pattern to specify what to look for in the log event message.</p>
    pub fn set_filter_pattern(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_pattern = input;
        self
    }
    /// <p>A symbolic description of how CloudWatch Logs should interpret the data in each log event. For example, a log event can contain timestamps, IP addresses, strings, and so on. You use the filter pattern to specify what to look for in the log event message.</p>
    pub fn get_filter_pattern(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_pattern
    }
    /// Appends an item to `log_event_messages`.
    ///
    /// To override the contents of this collection use [`set_log_event_messages`](Self::set_log_event_messages).
    ///
    /// <p>The log event messages to test.</p>
    pub fn log_event_messages(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.log_event_messages.unwrap_or_default();
        v.push(input.into());
        self.log_event_messages = ::std::option::Option::Some(v);
        self
    }
    /// <p>The log event messages to test.</p>
    pub fn set_log_event_messages(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.log_event_messages = input;
        self
    }
    /// <p>The log event messages to test.</p>
    pub fn get_log_event_messages(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.log_event_messages
    }
    /// Consumes the builder and constructs a [`TestMetricFilterInput`](crate::operation::test_metric_filter::TestMetricFilterInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::test_metric_filter::TestMetricFilterInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::test_metric_filter::TestMetricFilterInput {
            filter_pattern: self.filter_pattern,
            log_event_messages: self.log_event_messages,
        })
    }
}
