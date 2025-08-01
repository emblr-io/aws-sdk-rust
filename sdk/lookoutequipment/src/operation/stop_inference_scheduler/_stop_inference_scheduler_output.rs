// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopInferenceSchedulerOutput {
    /// <p>The Amazon Resource Name (ARN) of the machine learning model used by the inference scheduler being stopped.</p>
    pub model_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the machine learning model used by the inference scheduler being stopped.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the inference scheduler being stopped.</p>
    pub inference_scheduler_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the inference schedule being stopped.</p>
    pub inference_scheduler_arn: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the status of the inference scheduler.</p>
    pub status: ::std::option::Option<crate::types::InferenceSchedulerStatus>,
    _request_id: Option<String>,
}
impl StopInferenceSchedulerOutput {
    /// <p>The Amazon Resource Name (ARN) of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn model_arn(&self) -> ::std::option::Option<&str> {
        self.model_arn.as_deref()
    }
    /// <p>The name of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
    /// <p>The name of the inference scheduler being stopped.</p>
    pub fn inference_scheduler_name(&self) -> ::std::option::Option<&str> {
        self.inference_scheduler_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the inference schedule being stopped.</p>
    pub fn inference_scheduler_arn(&self) -> ::std::option::Option<&str> {
        self.inference_scheduler_arn.as_deref()
    }
    /// <p>Indicates the status of the inference scheduler.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::InferenceSchedulerStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StopInferenceSchedulerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopInferenceSchedulerOutput {
    /// Creates a new builder-style object to manufacture [`StopInferenceSchedulerOutput`](crate::operation::stop_inference_scheduler::StopInferenceSchedulerOutput).
    pub fn builder() -> crate::operation::stop_inference_scheduler::builders::StopInferenceSchedulerOutputBuilder {
        crate::operation::stop_inference_scheduler::builders::StopInferenceSchedulerOutputBuilder::default()
    }
}

/// A builder for [`StopInferenceSchedulerOutput`](crate::operation::stop_inference_scheduler::StopInferenceSchedulerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopInferenceSchedulerOutputBuilder {
    pub(crate) model_arn: ::std::option::Option<::std::string::String>,
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
    pub(crate) inference_scheduler_name: ::std::option::Option<::std::string::String>,
    pub(crate) inference_scheduler_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::InferenceSchedulerStatus>,
    _request_id: Option<String>,
}
impl StopInferenceSchedulerOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn model_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn set_model_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn get_model_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_arn
    }
    /// <p>The name of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the machine learning model used by the inference scheduler being stopped.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// <p>The name of the inference scheduler being stopped.</p>
    pub fn inference_scheduler_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_scheduler_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the inference scheduler being stopped.</p>
    pub fn set_inference_scheduler_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_scheduler_name = input;
        self
    }
    /// <p>The name of the inference scheduler being stopped.</p>
    pub fn get_inference_scheduler_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_scheduler_name
    }
    /// <p>The Amazon Resource Name (ARN) of the inference schedule being stopped.</p>
    pub fn inference_scheduler_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_scheduler_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the inference schedule being stopped.</p>
    pub fn set_inference_scheduler_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_scheduler_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the inference schedule being stopped.</p>
    pub fn get_inference_scheduler_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_scheduler_arn
    }
    /// <p>Indicates the status of the inference scheduler.</p>
    pub fn status(mut self, input: crate::types::InferenceSchedulerStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the status of the inference scheduler.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::InferenceSchedulerStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Indicates the status of the inference scheduler.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::InferenceSchedulerStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopInferenceSchedulerOutput`](crate::operation::stop_inference_scheduler::StopInferenceSchedulerOutput).
    pub fn build(self) -> crate::operation::stop_inference_scheduler::StopInferenceSchedulerOutput {
        crate::operation::stop_inference_scheduler::StopInferenceSchedulerOutput {
            model_arn: self.model_arn,
            model_name: self.model_name,
            inference_scheduler_name: self.inference_scheduler_name,
            inference_scheduler_arn: self.inference_scheduler_arn,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
