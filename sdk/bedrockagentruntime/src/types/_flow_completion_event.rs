// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about why a flow completed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct FlowCompletionEvent {
    /// <p>The reason that the flow completed.</p>
    pub completion_reason: crate::types::FlowCompletionReason,
}
impl FlowCompletionEvent {
    /// <p>The reason that the flow completed.</p>
    pub fn completion_reason(&self) -> &crate::types::FlowCompletionReason {
        &self.completion_reason
    }
}
impl ::std::fmt::Debug for FlowCompletionEvent {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FlowCompletionEvent");
        formatter.field("completion_reason", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl FlowCompletionEvent {
    /// Creates a new builder-style object to manufacture [`FlowCompletionEvent`](crate::types::FlowCompletionEvent).
    pub fn builder() -> crate::types::builders::FlowCompletionEventBuilder {
        crate::types::builders::FlowCompletionEventBuilder::default()
    }
}

/// A builder for [`FlowCompletionEvent`](crate::types::FlowCompletionEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct FlowCompletionEventBuilder {
    pub(crate) completion_reason: ::std::option::Option<crate::types::FlowCompletionReason>,
}
impl FlowCompletionEventBuilder {
    /// <p>The reason that the flow completed.</p>
    /// This field is required.
    pub fn completion_reason(mut self, input: crate::types::FlowCompletionReason) -> Self {
        self.completion_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason that the flow completed.</p>
    pub fn set_completion_reason(mut self, input: ::std::option::Option<crate::types::FlowCompletionReason>) -> Self {
        self.completion_reason = input;
        self
    }
    /// <p>The reason that the flow completed.</p>
    pub fn get_completion_reason(&self) -> &::std::option::Option<crate::types::FlowCompletionReason> {
        &self.completion_reason
    }
    /// Consumes the builder and constructs a [`FlowCompletionEvent`](crate::types::FlowCompletionEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`completion_reason`](crate::types::builders::FlowCompletionEventBuilder::completion_reason)
    pub fn build(self) -> ::std::result::Result<crate::types::FlowCompletionEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FlowCompletionEvent {
            completion_reason: self.completion_reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "completion_reason",
                    "completion_reason was not specified but it is required when building FlowCompletionEvent",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for FlowCompletionEventBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("FlowCompletionEventBuilder");
        formatter.field("completion_reason", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
