// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The start and end times of an inference experiment.</p>
/// <p>The maximum duration that you can set for an inference experiment is 30 days.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferenceExperimentSchedule {
    /// <p>The timestamp at which the inference experiment started or will start.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp at which the inference experiment ended or will end.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl InferenceExperimentSchedule {
    /// <p>The timestamp at which the inference experiment started or will start.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The timestamp at which the inference experiment ended or will end.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl InferenceExperimentSchedule {
    /// Creates a new builder-style object to manufacture [`InferenceExperimentSchedule`](crate::types::InferenceExperimentSchedule).
    pub fn builder() -> crate::types::builders::InferenceExperimentScheduleBuilder {
        crate::types::builders::InferenceExperimentScheduleBuilder::default()
    }
}

/// A builder for [`InferenceExperimentSchedule`](crate::types::InferenceExperimentSchedule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferenceExperimentScheduleBuilder {
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl InferenceExperimentScheduleBuilder {
    /// <p>The timestamp at which the inference experiment started or will start.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the inference experiment started or will start.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The timestamp at which the inference experiment started or will start.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The timestamp at which the inference experiment ended or will end.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the inference experiment ended or will end.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The timestamp at which the inference experiment ended or will end.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`InferenceExperimentSchedule`](crate::types::InferenceExperimentSchedule).
    pub fn build(self) -> crate::types::InferenceExperimentSchedule {
        crate::types::InferenceExperimentSchedule {
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
}
