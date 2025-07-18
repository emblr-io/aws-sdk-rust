// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartSpeechSynthesisTaskOutput {
    /// <p>SynthesisTask object that provides information and attributes about a newly submitted speech synthesis task.</p>
    pub synthesis_task: ::std::option::Option<crate::types::SynthesisTask>,
    _request_id: Option<String>,
}
impl StartSpeechSynthesisTaskOutput {
    /// <p>SynthesisTask object that provides information and attributes about a newly submitted speech synthesis task.</p>
    pub fn synthesis_task(&self) -> ::std::option::Option<&crate::types::SynthesisTask> {
        self.synthesis_task.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StartSpeechSynthesisTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartSpeechSynthesisTaskOutput {
    /// Creates a new builder-style object to manufacture [`StartSpeechSynthesisTaskOutput`](crate::operation::start_speech_synthesis_task::StartSpeechSynthesisTaskOutput).
    pub fn builder() -> crate::operation::start_speech_synthesis_task::builders::StartSpeechSynthesisTaskOutputBuilder {
        crate::operation::start_speech_synthesis_task::builders::StartSpeechSynthesisTaskOutputBuilder::default()
    }
}

/// A builder for [`StartSpeechSynthesisTaskOutput`](crate::operation::start_speech_synthesis_task::StartSpeechSynthesisTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartSpeechSynthesisTaskOutputBuilder {
    pub(crate) synthesis_task: ::std::option::Option<crate::types::SynthesisTask>,
    _request_id: Option<String>,
}
impl StartSpeechSynthesisTaskOutputBuilder {
    /// <p>SynthesisTask object that provides information and attributes about a newly submitted speech synthesis task.</p>
    pub fn synthesis_task(mut self, input: crate::types::SynthesisTask) -> Self {
        self.synthesis_task = ::std::option::Option::Some(input);
        self
    }
    /// <p>SynthesisTask object that provides information and attributes about a newly submitted speech synthesis task.</p>
    pub fn set_synthesis_task(mut self, input: ::std::option::Option<crate::types::SynthesisTask>) -> Self {
        self.synthesis_task = input;
        self
    }
    /// <p>SynthesisTask object that provides information and attributes about a newly submitted speech synthesis task.</p>
    pub fn get_synthesis_task(&self) -> &::std::option::Option<crate::types::SynthesisTask> {
        &self.synthesis_task
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartSpeechSynthesisTaskOutput`](crate::operation::start_speech_synthesis_task::StartSpeechSynthesisTaskOutput).
    pub fn build(self) -> crate::operation::start_speech_synthesis_task::StartSpeechSynthesisTaskOutput {
        crate::operation::start_speech_synthesis_task::StartSpeechSynthesisTaskOutput {
            synthesis_task: self.synthesis_task,
            _request_id: self._request_id,
        }
    }
}
