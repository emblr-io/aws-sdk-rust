// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateScheduleOutput {
    /// <p>The Amazon Resource Name (ARN) of the schedule that you updated.</p>
    pub schedule_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl UpdateScheduleOutput {
    /// <p>The Amazon Resource Name (ARN) of the schedule that you updated.</p>
    pub fn schedule_arn(&self) -> &str {
        use std::ops::Deref;
        self.schedule_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateScheduleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateScheduleOutput {
    /// Creates a new builder-style object to manufacture [`UpdateScheduleOutput`](crate::operation::update_schedule::UpdateScheduleOutput).
    pub fn builder() -> crate::operation::update_schedule::builders::UpdateScheduleOutputBuilder {
        crate::operation::update_schedule::builders::UpdateScheduleOutputBuilder::default()
    }
}

/// A builder for [`UpdateScheduleOutput`](crate::operation::update_schedule::UpdateScheduleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateScheduleOutputBuilder {
    pub(crate) schedule_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateScheduleOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the schedule that you updated.</p>
    /// This field is required.
    pub fn schedule_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schedule_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the schedule that you updated.</p>
    pub fn set_schedule_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schedule_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the schedule that you updated.</p>
    pub fn get_schedule_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.schedule_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateScheduleOutput`](crate::operation::update_schedule::UpdateScheduleOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`schedule_arn`](crate::operation::update_schedule::builders::UpdateScheduleOutputBuilder::schedule_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_schedule::UpdateScheduleOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_schedule::UpdateScheduleOutput {
            schedule_arn: self.schedule_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "schedule_arn",
                    "schedule_arn was not specified but it is required when building UpdateScheduleOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
