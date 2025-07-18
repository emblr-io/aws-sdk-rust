// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApproveAssignmentInput {
    /// <p>The ID of the assignment. The assignment must correspond to a HIT created by the Requester.</p>
    pub assignment_id: ::std::option::Option<::std::string::String>,
    /// <p>A message for the Worker, which the Worker can see in the Status section of the web site.</p>
    pub requester_feedback: ::std::option::Option<::std::string::String>,
    /// <p>A flag indicating that an assignment should be approved even if it was previously rejected. Defaults to <code>False</code>.</p>
    pub override_rejection: ::std::option::Option<bool>,
}
impl ApproveAssignmentInput {
    /// <p>The ID of the assignment. The assignment must correspond to a HIT created by the Requester.</p>
    pub fn assignment_id(&self) -> ::std::option::Option<&str> {
        self.assignment_id.as_deref()
    }
    /// <p>A message for the Worker, which the Worker can see in the Status section of the web site.</p>
    pub fn requester_feedback(&self) -> ::std::option::Option<&str> {
        self.requester_feedback.as_deref()
    }
    /// <p>A flag indicating that an assignment should be approved even if it was previously rejected. Defaults to <code>False</code>.</p>
    pub fn override_rejection(&self) -> ::std::option::Option<bool> {
        self.override_rejection
    }
}
impl ApproveAssignmentInput {
    /// Creates a new builder-style object to manufacture [`ApproveAssignmentInput`](crate::operation::approve_assignment::ApproveAssignmentInput).
    pub fn builder() -> crate::operation::approve_assignment::builders::ApproveAssignmentInputBuilder {
        crate::operation::approve_assignment::builders::ApproveAssignmentInputBuilder::default()
    }
}

/// A builder for [`ApproveAssignmentInput`](crate::operation::approve_assignment::ApproveAssignmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApproveAssignmentInputBuilder {
    pub(crate) assignment_id: ::std::option::Option<::std::string::String>,
    pub(crate) requester_feedback: ::std::option::Option<::std::string::String>,
    pub(crate) override_rejection: ::std::option::Option<bool>,
}
impl ApproveAssignmentInputBuilder {
    /// <p>The ID of the assignment. The assignment must correspond to a HIT created by the Requester.</p>
    /// This field is required.
    pub fn assignment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.assignment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the assignment. The assignment must correspond to a HIT created by the Requester.</p>
    pub fn set_assignment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.assignment_id = input;
        self
    }
    /// <p>The ID of the assignment. The assignment must correspond to a HIT created by the Requester.</p>
    pub fn get_assignment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.assignment_id
    }
    /// <p>A message for the Worker, which the Worker can see in the Status section of the web site.</p>
    pub fn requester_feedback(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.requester_feedback = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message for the Worker, which the Worker can see in the Status section of the web site.</p>
    pub fn set_requester_feedback(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.requester_feedback = input;
        self
    }
    /// <p>A message for the Worker, which the Worker can see in the Status section of the web site.</p>
    pub fn get_requester_feedback(&self) -> &::std::option::Option<::std::string::String> {
        &self.requester_feedback
    }
    /// <p>A flag indicating that an assignment should be approved even if it was previously rejected. Defaults to <code>False</code>.</p>
    pub fn override_rejection(mut self, input: bool) -> Self {
        self.override_rejection = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag indicating that an assignment should be approved even if it was previously rejected. Defaults to <code>False</code>.</p>
    pub fn set_override_rejection(mut self, input: ::std::option::Option<bool>) -> Self {
        self.override_rejection = input;
        self
    }
    /// <p>A flag indicating that an assignment should be approved even if it was previously rejected. Defaults to <code>False</code>.</p>
    pub fn get_override_rejection(&self) -> &::std::option::Option<bool> {
        &self.override_rejection
    }
    /// Consumes the builder and constructs a [`ApproveAssignmentInput`](crate::operation::approve_assignment::ApproveAssignmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::approve_assignment::ApproveAssignmentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::approve_assignment::ApproveAssignmentInput {
            assignment_id: self.assignment_id,
            requester_feedback: self.requester_feedback,
            override_rejection: self.override_rejection,
        })
    }
}
