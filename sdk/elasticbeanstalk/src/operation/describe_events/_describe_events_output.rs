// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Result message wrapping a list of event descriptions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEventsOutput {
    /// <p>A list of <code>EventDescription</code>.</p>
    pub events: ::std::option::Option<::std::vec::Vec<crate::types::EventDescription>>,
    /// <p>If returned, this indicates that there are more results to obtain. Use this token in the next <code>DescribeEvents</code> call to get the next batch of events.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeEventsOutput {
    /// <p>A list of <code>EventDescription</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.events.is_none()`.
    pub fn events(&self) -> &[crate::types::EventDescription] {
        self.events.as_deref().unwrap_or_default()
    }
    /// <p>If returned, this indicates that there are more results to obtain. Use this token in the next <code>DescribeEvents</code> call to get the next batch of events.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeEventsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeEventsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeEventsOutput`](crate::operation::describe_events::DescribeEventsOutput).
    pub fn builder() -> crate::operation::describe_events::builders::DescribeEventsOutputBuilder {
        crate::operation::describe_events::builders::DescribeEventsOutputBuilder::default()
    }
}

/// A builder for [`DescribeEventsOutput`](crate::operation::describe_events::DescribeEventsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEventsOutputBuilder {
    pub(crate) events: ::std::option::Option<::std::vec::Vec<crate::types::EventDescription>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeEventsOutputBuilder {
    /// Appends an item to `events`.
    ///
    /// To override the contents of this collection use [`set_events`](Self::set_events).
    ///
    /// <p>A list of <code>EventDescription</code>.</p>
    pub fn events(mut self, input: crate::types::EventDescription) -> Self {
        let mut v = self.events.unwrap_or_default();
        v.push(input);
        self.events = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>EventDescription</code>.</p>
    pub fn set_events(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventDescription>>) -> Self {
        self.events = input;
        self
    }
    /// <p>A list of <code>EventDescription</code>.</p>
    pub fn get_events(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventDescription>> {
        &self.events
    }
    /// <p>If returned, this indicates that there are more results to obtain. Use this token in the next <code>DescribeEvents</code> call to get the next batch of events.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If returned, this indicates that there are more results to obtain. Use this token in the next <code>DescribeEvents</code> call to get the next batch of events.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If returned, this indicates that there are more results to obtain. Use this token in the next <code>DescribeEvents</code> call to get the next batch of events.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeEventsOutput`](crate::operation::describe_events::DescribeEventsOutput).
    pub fn build(self) -> crate::operation::describe_events::DescribeEventsOutput {
        crate::operation::describe_events::DescribeEventsOutput {
            events: self.events,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
