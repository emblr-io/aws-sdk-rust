// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateStageOutput {
    /// <p>The stage that was created.</p>
    pub stage: ::std::option::Option<crate::types::Stage>,
    /// <p>Participant tokens attached to the stage. These correspond to the <code>participants</code> in the request.</p>
    pub participant_tokens: ::std::option::Option<::std::vec::Vec<crate::types::ParticipantToken>>,
    _request_id: Option<String>,
}
impl CreateStageOutput {
    /// <p>The stage that was created.</p>
    pub fn stage(&self) -> ::std::option::Option<&crate::types::Stage> {
        self.stage.as_ref()
    }
    /// <p>Participant tokens attached to the stage. These correspond to the <code>participants</code> in the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.participant_tokens.is_none()`.
    pub fn participant_tokens(&self) -> &[crate::types::ParticipantToken] {
        self.participant_tokens.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CreateStageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateStageOutput {
    /// Creates a new builder-style object to manufacture [`CreateStageOutput`](crate::operation::create_stage::CreateStageOutput).
    pub fn builder() -> crate::operation::create_stage::builders::CreateStageOutputBuilder {
        crate::operation::create_stage::builders::CreateStageOutputBuilder::default()
    }
}

/// A builder for [`CreateStageOutput`](crate::operation::create_stage::CreateStageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateStageOutputBuilder {
    pub(crate) stage: ::std::option::Option<crate::types::Stage>,
    pub(crate) participant_tokens: ::std::option::Option<::std::vec::Vec<crate::types::ParticipantToken>>,
    _request_id: Option<String>,
}
impl CreateStageOutputBuilder {
    /// <p>The stage that was created.</p>
    pub fn stage(mut self, input: crate::types::Stage) -> Self {
        self.stage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stage that was created.</p>
    pub fn set_stage(mut self, input: ::std::option::Option<crate::types::Stage>) -> Self {
        self.stage = input;
        self
    }
    /// <p>The stage that was created.</p>
    pub fn get_stage(&self) -> &::std::option::Option<crate::types::Stage> {
        &self.stage
    }
    /// Appends an item to `participant_tokens`.
    ///
    /// To override the contents of this collection use [`set_participant_tokens`](Self::set_participant_tokens).
    ///
    /// <p>Participant tokens attached to the stage. These correspond to the <code>participants</code> in the request.</p>
    pub fn participant_tokens(mut self, input: crate::types::ParticipantToken) -> Self {
        let mut v = self.participant_tokens.unwrap_or_default();
        v.push(input);
        self.participant_tokens = ::std::option::Option::Some(v);
        self
    }
    /// <p>Participant tokens attached to the stage. These correspond to the <code>participants</code> in the request.</p>
    pub fn set_participant_tokens(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParticipantToken>>) -> Self {
        self.participant_tokens = input;
        self
    }
    /// <p>Participant tokens attached to the stage. These correspond to the <code>participants</code> in the request.</p>
    pub fn get_participant_tokens(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParticipantToken>> {
        &self.participant_tokens
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateStageOutput`](crate::operation::create_stage::CreateStageOutput).
    pub fn build(self) -> crate::operation::create_stage::CreateStageOutput {
        crate::operation::create_stage::CreateStageOutput {
            stage: self.stage,
            participant_tokens: self.participant_tokens,
            _request_id: self._request_id,
        }
    }
}
