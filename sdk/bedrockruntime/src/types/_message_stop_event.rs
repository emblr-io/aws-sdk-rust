// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The stop event for a message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageStopEvent {
    /// <p>The reason why the model stopped generating output.</p>
    pub stop_reason: crate::types::StopReason,
    /// <p>The additional model response fields.</p>
    pub additional_model_response_fields: ::std::option::Option<::aws_smithy_types::Document>,
}
impl MessageStopEvent {
    /// <p>The reason why the model stopped generating output.</p>
    pub fn stop_reason(&self) -> &crate::types::StopReason {
        &self.stop_reason
    }
    /// <p>The additional model response fields.</p>
    pub fn additional_model_response_fields(&self) -> ::std::option::Option<&::aws_smithy_types::Document> {
        self.additional_model_response_fields.as_ref()
    }
}
impl MessageStopEvent {
    /// Creates a new builder-style object to manufacture [`MessageStopEvent`](crate::types::MessageStopEvent).
    pub fn builder() -> crate::types::builders::MessageStopEventBuilder {
        crate::types::builders::MessageStopEventBuilder::default()
    }
}

/// A builder for [`MessageStopEvent`](crate::types::MessageStopEvent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageStopEventBuilder {
    pub(crate) stop_reason: ::std::option::Option<crate::types::StopReason>,
    pub(crate) additional_model_response_fields: ::std::option::Option<::aws_smithy_types::Document>,
}
impl MessageStopEventBuilder {
    /// <p>The reason why the model stopped generating output.</p>
    /// This field is required.
    pub fn stop_reason(mut self, input: crate::types::StopReason) -> Self {
        self.stop_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason why the model stopped generating output.</p>
    pub fn set_stop_reason(mut self, input: ::std::option::Option<crate::types::StopReason>) -> Self {
        self.stop_reason = input;
        self
    }
    /// <p>The reason why the model stopped generating output.</p>
    pub fn get_stop_reason(&self) -> &::std::option::Option<crate::types::StopReason> {
        &self.stop_reason
    }
    /// <p>The additional model response fields.</p>
    pub fn additional_model_response_fields(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.additional_model_response_fields = ::std::option::Option::Some(input);
        self
    }
    /// <p>The additional model response fields.</p>
    pub fn set_additional_model_response_fields(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.additional_model_response_fields = input;
        self
    }
    /// <p>The additional model response fields.</p>
    pub fn get_additional_model_response_fields(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.additional_model_response_fields
    }
    /// Consumes the builder and constructs a [`MessageStopEvent`](crate::types::MessageStopEvent).
    /// This method will fail if any of the following fields are not set:
    /// - [`stop_reason`](crate::types::builders::MessageStopEventBuilder::stop_reason)
    pub fn build(self) -> ::std::result::Result<crate::types::MessageStopEvent, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MessageStopEvent {
            stop_reason: self.stop_reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stop_reason",
                    "stop_reason was not specified but it is required when building MessageStopEvent",
                )
            })?,
            additional_model_response_fields: self.additional_model_response_fields,
        })
    }
}
