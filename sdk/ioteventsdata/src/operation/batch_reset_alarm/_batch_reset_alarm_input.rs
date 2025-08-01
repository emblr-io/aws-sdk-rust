// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchResetAlarmInput {
    /// <p>The list of reset action requests. You can specify up to 10 requests per operation.</p>
    pub reset_action_requests: ::std::option::Option<::std::vec::Vec<crate::types::ResetAlarmActionRequest>>,
}
impl BatchResetAlarmInput {
    /// <p>The list of reset action requests. You can specify up to 10 requests per operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reset_action_requests.is_none()`.
    pub fn reset_action_requests(&self) -> &[crate::types::ResetAlarmActionRequest] {
        self.reset_action_requests.as_deref().unwrap_or_default()
    }
}
impl BatchResetAlarmInput {
    /// Creates a new builder-style object to manufacture [`BatchResetAlarmInput`](crate::operation::batch_reset_alarm::BatchResetAlarmInput).
    pub fn builder() -> crate::operation::batch_reset_alarm::builders::BatchResetAlarmInputBuilder {
        crate::operation::batch_reset_alarm::builders::BatchResetAlarmInputBuilder::default()
    }
}

/// A builder for [`BatchResetAlarmInput`](crate::operation::batch_reset_alarm::BatchResetAlarmInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchResetAlarmInputBuilder {
    pub(crate) reset_action_requests: ::std::option::Option<::std::vec::Vec<crate::types::ResetAlarmActionRequest>>,
}
impl BatchResetAlarmInputBuilder {
    /// Appends an item to `reset_action_requests`.
    ///
    /// To override the contents of this collection use [`set_reset_action_requests`](Self::set_reset_action_requests).
    ///
    /// <p>The list of reset action requests. You can specify up to 10 requests per operation.</p>
    pub fn reset_action_requests(mut self, input: crate::types::ResetAlarmActionRequest) -> Self {
        let mut v = self.reset_action_requests.unwrap_or_default();
        v.push(input);
        self.reset_action_requests = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of reset action requests. You can specify up to 10 requests per operation.</p>
    pub fn set_reset_action_requests(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResetAlarmActionRequest>>) -> Self {
        self.reset_action_requests = input;
        self
    }
    /// <p>The list of reset action requests. You can specify up to 10 requests per operation.</p>
    pub fn get_reset_action_requests(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResetAlarmActionRequest>> {
        &self.reset_action_requests
    }
    /// Consumes the builder and constructs a [`BatchResetAlarmInput`](crate::operation::batch_reset_alarm::BatchResetAlarmInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_reset_alarm::BatchResetAlarmInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::batch_reset_alarm::BatchResetAlarmInput {
            reset_action_requests: self.reset_action_requests,
        })
    }
}
