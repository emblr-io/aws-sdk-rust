// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopContinuousExportOutput {
    /// <p>Timestamp that represents when this continuous export started collecting data.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Timestamp that represents when this continuous export was stopped.</p>
    pub stop_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StopContinuousExportOutput {
    /// <p>Timestamp that represents when this continuous export started collecting data.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>Timestamp that represents when this continuous export was stopped.</p>
    pub fn stop_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.stop_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StopContinuousExportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopContinuousExportOutput {
    /// Creates a new builder-style object to manufacture [`StopContinuousExportOutput`](crate::operation::stop_continuous_export::StopContinuousExportOutput).
    pub fn builder() -> crate::operation::stop_continuous_export::builders::StopContinuousExportOutputBuilder {
        crate::operation::stop_continuous_export::builders::StopContinuousExportOutputBuilder::default()
    }
}

/// A builder for [`StopContinuousExportOutput`](crate::operation::stop_continuous_export::StopContinuousExportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopContinuousExportOutputBuilder {
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) stop_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StopContinuousExportOutputBuilder {
    /// <p>Timestamp that represents when this continuous export started collecting data.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Timestamp that represents when this continuous export started collecting data.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>Timestamp that represents when this continuous export started collecting data.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>Timestamp that represents when this continuous export was stopped.</p>
    pub fn stop_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.stop_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Timestamp that represents when this continuous export was stopped.</p>
    pub fn set_stop_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.stop_time = input;
        self
    }
    /// <p>Timestamp that represents when this continuous export was stopped.</p>
    pub fn get_stop_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.stop_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopContinuousExportOutput`](crate::operation::stop_continuous_export::StopContinuousExportOutput).
    pub fn build(self) -> crate::operation::stop_continuous_export::StopContinuousExportOutput {
        crate::operation::stop_continuous_export::StopContinuousExportOutput {
            start_time: self.start_time,
            stop_time: self.stop_time,
            _request_id: self._request_id,
        }
    }
}
