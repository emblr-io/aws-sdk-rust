// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct BatchCreateDelegationByAssessmentOutput {
    /// <p>The delegations that are associated with the assessment.</p>
    pub delegations: ::std::option::Option<::std::vec::Vec<crate::types::Delegation>>,
    /// <p>A list of errors that the <code>BatchCreateDelegationByAssessment</code> API returned.</p>
    pub errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchCreateDelegationByAssessmentError>>,
    _request_id: Option<String>,
}
impl BatchCreateDelegationByAssessmentOutput {
    /// <p>The delegations that are associated with the assessment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.delegations.is_none()`.
    pub fn delegations(&self) -> &[crate::types::Delegation] {
        self.delegations.as_deref().unwrap_or_default()
    }
    /// <p>A list of errors that the <code>BatchCreateDelegationByAssessment</code> API returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.errors.is_none()`.
    pub fn errors(&self) -> &[crate::types::BatchCreateDelegationByAssessmentError] {
        self.errors.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for BatchCreateDelegationByAssessmentOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("BatchCreateDelegationByAssessmentOutput");
        formatter.field("delegations", &"*** Sensitive Data Redacted ***");
        formatter.field("errors", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for BatchCreateDelegationByAssessmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchCreateDelegationByAssessmentOutput {
    /// Creates a new builder-style object to manufacture [`BatchCreateDelegationByAssessmentOutput`](crate::operation::batch_create_delegation_by_assessment::BatchCreateDelegationByAssessmentOutput).
    pub fn builder() -> crate::operation::batch_create_delegation_by_assessment::builders::BatchCreateDelegationByAssessmentOutputBuilder {
        crate::operation::batch_create_delegation_by_assessment::builders::BatchCreateDelegationByAssessmentOutputBuilder::default()
    }
}

/// A builder for [`BatchCreateDelegationByAssessmentOutput`](crate::operation::batch_create_delegation_by_assessment::BatchCreateDelegationByAssessmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct BatchCreateDelegationByAssessmentOutputBuilder {
    pub(crate) delegations: ::std::option::Option<::std::vec::Vec<crate::types::Delegation>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchCreateDelegationByAssessmentError>>,
    _request_id: Option<String>,
}
impl BatchCreateDelegationByAssessmentOutputBuilder {
    /// Appends an item to `delegations`.
    ///
    /// To override the contents of this collection use [`set_delegations`](Self::set_delegations).
    ///
    /// <p>The delegations that are associated with the assessment.</p>
    pub fn delegations(mut self, input: crate::types::Delegation) -> Self {
        let mut v = self.delegations.unwrap_or_default();
        v.push(input);
        self.delegations = ::std::option::Option::Some(v);
        self
    }
    /// <p>The delegations that are associated with the assessment.</p>
    pub fn set_delegations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Delegation>>) -> Self {
        self.delegations = input;
        self
    }
    /// <p>The delegations that are associated with the assessment.</p>
    pub fn get_delegations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Delegation>> {
        &self.delegations
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>A list of errors that the <code>BatchCreateDelegationByAssessment</code> API returned.</p>
    pub fn errors(mut self, input: crate::types::BatchCreateDelegationByAssessmentError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of errors that the <code>BatchCreateDelegationByAssessment</code> API returned.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchCreateDelegationByAssessmentError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>A list of errors that the <code>BatchCreateDelegationByAssessment</code> API returned.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchCreateDelegationByAssessmentError>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchCreateDelegationByAssessmentOutput`](crate::operation::batch_create_delegation_by_assessment::BatchCreateDelegationByAssessmentOutput).
    pub fn build(self) -> crate::operation::batch_create_delegation_by_assessment::BatchCreateDelegationByAssessmentOutput {
        crate::operation::batch_create_delegation_by_assessment::BatchCreateDelegationByAssessmentOutput {
            delegations: self.delegations,
            errors: self.errors,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for BatchCreateDelegationByAssessmentOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("BatchCreateDelegationByAssessmentOutputBuilder");
        formatter.field("delegations", &"*** Sensitive Data Redacted ***");
        formatter.field("errors", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
