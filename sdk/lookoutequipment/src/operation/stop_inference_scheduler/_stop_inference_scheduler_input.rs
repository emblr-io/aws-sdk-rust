// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopInferenceSchedulerInput {
    /// <p>The name of the inference scheduler to be stopped.</p>
    pub inference_scheduler_name: ::std::option::Option<::std::string::String>,
}
impl StopInferenceSchedulerInput {
    /// <p>The name of the inference scheduler to be stopped.</p>
    pub fn inference_scheduler_name(&self) -> ::std::option::Option<&str> {
        self.inference_scheduler_name.as_deref()
    }
}
impl StopInferenceSchedulerInput {
    /// Creates a new builder-style object to manufacture [`StopInferenceSchedulerInput`](crate::operation::stop_inference_scheduler::StopInferenceSchedulerInput).
    pub fn builder() -> crate::operation::stop_inference_scheduler::builders::StopInferenceSchedulerInputBuilder {
        crate::operation::stop_inference_scheduler::builders::StopInferenceSchedulerInputBuilder::default()
    }
}

/// A builder for [`StopInferenceSchedulerInput`](crate::operation::stop_inference_scheduler::StopInferenceSchedulerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopInferenceSchedulerInputBuilder {
    pub(crate) inference_scheduler_name: ::std::option::Option<::std::string::String>,
}
impl StopInferenceSchedulerInputBuilder {
    /// <p>The name of the inference scheduler to be stopped.</p>
    /// This field is required.
    pub fn inference_scheduler_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_scheduler_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the inference scheduler to be stopped.</p>
    pub fn set_inference_scheduler_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_scheduler_name = input;
        self
    }
    /// <p>The name of the inference scheduler to be stopped.</p>
    pub fn get_inference_scheduler_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_scheduler_name
    }
    /// Consumes the builder and constructs a [`StopInferenceSchedulerInput`](crate::operation::stop_inference_scheduler::StopInferenceSchedulerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::stop_inference_scheduler::StopInferenceSchedulerInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::stop_inference_scheduler::StopInferenceSchedulerInput {
            inference_scheduler_name: self.inference_scheduler_name,
        })
    }
}
