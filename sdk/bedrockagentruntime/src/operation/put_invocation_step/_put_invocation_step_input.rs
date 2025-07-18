// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutInvocationStepInput {
    /// <p>The unique identifier for the session to add the invocation step to. You can specify either the session's <code>sessionId</code> or its Amazon Resource Name (ARN).</p>
    pub session_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier (in UUID format) of the invocation to add the invocation step to.</p>
    pub invocation_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp for when the invocation step occurred.</p>
    pub invocation_step_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The payload for the invocation step, including text and images for the interaction.</p>
    pub payload: ::std::option::Option<crate::types::InvocationStepPayload>,
    /// <p>The unique identifier of the invocation step in UUID format.</p>
    pub invocation_step_id: ::std::option::Option<::std::string::String>,
}
impl PutInvocationStepInput {
    /// <p>The unique identifier for the session to add the invocation step to. You can specify either the session's <code>sessionId</code> or its Amazon Resource Name (ARN).</p>
    pub fn session_identifier(&self) -> ::std::option::Option<&str> {
        self.session_identifier.as_deref()
    }
    /// <p>The unique identifier (in UUID format) of the invocation to add the invocation step to.</p>
    pub fn invocation_identifier(&self) -> ::std::option::Option<&str> {
        self.invocation_identifier.as_deref()
    }
    /// <p>The timestamp for when the invocation step occurred.</p>
    pub fn invocation_step_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.invocation_step_time.as_ref()
    }
    /// <p>The payload for the invocation step, including text and images for the interaction.</p>
    pub fn payload(&self) -> ::std::option::Option<&crate::types::InvocationStepPayload> {
        self.payload.as_ref()
    }
    /// <p>The unique identifier of the invocation step in UUID format.</p>
    pub fn invocation_step_id(&self) -> ::std::option::Option<&str> {
        self.invocation_step_id.as_deref()
    }
}
impl PutInvocationStepInput {
    /// Creates a new builder-style object to manufacture [`PutInvocationStepInput`](crate::operation::put_invocation_step::PutInvocationStepInput).
    pub fn builder() -> crate::operation::put_invocation_step::builders::PutInvocationStepInputBuilder {
        crate::operation::put_invocation_step::builders::PutInvocationStepInputBuilder::default()
    }
}

/// A builder for [`PutInvocationStepInput`](crate::operation::put_invocation_step::PutInvocationStepInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutInvocationStepInputBuilder {
    pub(crate) session_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) invocation_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) invocation_step_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) payload: ::std::option::Option<crate::types::InvocationStepPayload>,
    pub(crate) invocation_step_id: ::std::option::Option<::std::string::String>,
}
impl PutInvocationStepInputBuilder {
    /// <p>The unique identifier for the session to add the invocation step to. You can specify either the session's <code>sessionId</code> or its Amazon Resource Name (ARN).</p>
    /// This field is required.
    pub fn session_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the session to add the invocation step to. You can specify either the session's <code>sessionId</code> or its Amazon Resource Name (ARN).</p>
    pub fn set_session_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_identifier = input;
        self
    }
    /// <p>The unique identifier for the session to add the invocation step to. You can specify either the session's <code>sessionId</code> or its Amazon Resource Name (ARN).</p>
    pub fn get_session_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_identifier
    }
    /// <p>The unique identifier (in UUID format) of the invocation to add the invocation step to.</p>
    /// This field is required.
    pub fn invocation_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invocation_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier (in UUID format) of the invocation to add the invocation step to.</p>
    pub fn set_invocation_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invocation_identifier = input;
        self
    }
    /// <p>The unique identifier (in UUID format) of the invocation to add the invocation step to.</p>
    pub fn get_invocation_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.invocation_identifier
    }
    /// <p>The timestamp for when the invocation step occurred.</p>
    /// This field is required.
    pub fn invocation_step_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.invocation_step_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp for when the invocation step occurred.</p>
    pub fn set_invocation_step_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.invocation_step_time = input;
        self
    }
    /// <p>The timestamp for when the invocation step occurred.</p>
    pub fn get_invocation_step_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.invocation_step_time
    }
    /// <p>The payload for the invocation step, including text and images for the interaction.</p>
    /// This field is required.
    pub fn payload(mut self, input: crate::types::InvocationStepPayload) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>The payload for the invocation step, including text and images for the interaction.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<crate::types::InvocationStepPayload>) -> Self {
        self.payload = input;
        self
    }
    /// <p>The payload for the invocation step, including text and images for the interaction.</p>
    pub fn get_payload(&self) -> &::std::option::Option<crate::types::InvocationStepPayload> {
        &self.payload
    }
    /// <p>The unique identifier of the invocation step in UUID format.</p>
    pub fn invocation_step_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.invocation_step_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the invocation step in UUID format.</p>
    pub fn set_invocation_step_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.invocation_step_id = input;
        self
    }
    /// <p>The unique identifier of the invocation step in UUID format.</p>
    pub fn get_invocation_step_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.invocation_step_id
    }
    /// Consumes the builder and constructs a [`PutInvocationStepInput`](crate::operation::put_invocation_step::PutInvocationStepInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_invocation_step::PutInvocationStepInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_invocation_step::PutInvocationStepInput {
            session_identifier: self.session_identifier,
            invocation_identifier: self.invocation_identifier,
            invocation_step_time: self.invocation_step_time,
            payload: self.payload,
            invocation_step_id: self.invocation_step_id,
        })
    }
}
