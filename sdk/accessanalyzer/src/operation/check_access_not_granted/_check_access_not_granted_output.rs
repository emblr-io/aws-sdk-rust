// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CheckAccessNotGrantedOutput {
    /// <p>The result of the check for whether the access is allowed. If the result is <code>PASS</code>, the specified policy doesn't allow any of the specified permissions in the access object. If the result is <code>FAIL</code>, the specified policy might allow some or all of the permissions in the access object.</p>
    pub result: ::std::option::Option<crate::types::CheckAccessNotGrantedResult>,
    /// <p>The message indicating whether the specified access is allowed.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>A description of the reasoning of the result.</p>
    pub reasons: ::std::option::Option<::std::vec::Vec<crate::types::ReasonSummary>>,
    _request_id: Option<String>,
}
impl CheckAccessNotGrantedOutput {
    /// <p>The result of the check for whether the access is allowed. If the result is <code>PASS</code>, the specified policy doesn't allow any of the specified permissions in the access object. If the result is <code>FAIL</code>, the specified policy might allow some or all of the permissions in the access object.</p>
    pub fn result(&self) -> ::std::option::Option<&crate::types::CheckAccessNotGrantedResult> {
        self.result.as_ref()
    }
    /// <p>The message indicating whether the specified access is allowed.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>A description of the reasoning of the result.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reasons.is_none()`.
    pub fn reasons(&self) -> &[crate::types::ReasonSummary] {
        self.reasons.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CheckAccessNotGrantedOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CheckAccessNotGrantedOutput {
    /// Creates a new builder-style object to manufacture [`CheckAccessNotGrantedOutput`](crate::operation::check_access_not_granted::CheckAccessNotGrantedOutput).
    pub fn builder() -> crate::operation::check_access_not_granted::builders::CheckAccessNotGrantedOutputBuilder {
        crate::operation::check_access_not_granted::builders::CheckAccessNotGrantedOutputBuilder::default()
    }
}

/// A builder for [`CheckAccessNotGrantedOutput`](crate::operation::check_access_not_granted::CheckAccessNotGrantedOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CheckAccessNotGrantedOutputBuilder {
    pub(crate) result: ::std::option::Option<crate::types::CheckAccessNotGrantedResult>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) reasons: ::std::option::Option<::std::vec::Vec<crate::types::ReasonSummary>>,
    _request_id: Option<String>,
}
impl CheckAccessNotGrantedOutputBuilder {
    /// <p>The result of the check for whether the access is allowed. If the result is <code>PASS</code>, the specified policy doesn't allow any of the specified permissions in the access object. If the result is <code>FAIL</code>, the specified policy might allow some or all of the permissions in the access object.</p>
    pub fn result(mut self, input: crate::types::CheckAccessNotGrantedResult) -> Self {
        self.result = ::std::option::Option::Some(input);
        self
    }
    /// <p>The result of the check for whether the access is allowed. If the result is <code>PASS</code>, the specified policy doesn't allow any of the specified permissions in the access object. If the result is <code>FAIL</code>, the specified policy might allow some or all of the permissions in the access object.</p>
    pub fn set_result(mut self, input: ::std::option::Option<crate::types::CheckAccessNotGrantedResult>) -> Self {
        self.result = input;
        self
    }
    /// <p>The result of the check for whether the access is allowed. If the result is <code>PASS</code>, the specified policy doesn't allow any of the specified permissions in the access object. If the result is <code>FAIL</code>, the specified policy might allow some or all of the permissions in the access object.</p>
    pub fn get_result(&self) -> &::std::option::Option<crate::types::CheckAccessNotGrantedResult> {
        &self.result
    }
    /// <p>The message indicating whether the specified access is allowed.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message indicating whether the specified access is allowed.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The message indicating whether the specified access is allowed.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Appends an item to `reasons`.
    ///
    /// To override the contents of this collection use [`set_reasons`](Self::set_reasons).
    ///
    /// <p>A description of the reasoning of the result.</p>
    pub fn reasons(mut self, input: crate::types::ReasonSummary) -> Self {
        let mut v = self.reasons.unwrap_or_default();
        v.push(input);
        self.reasons = ::std::option::Option::Some(v);
        self
    }
    /// <p>A description of the reasoning of the result.</p>
    pub fn set_reasons(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReasonSummary>>) -> Self {
        self.reasons = input;
        self
    }
    /// <p>A description of the reasoning of the result.</p>
    pub fn get_reasons(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReasonSummary>> {
        &self.reasons
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CheckAccessNotGrantedOutput`](crate::operation::check_access_not_granted::CheckAccessNotGrantedOutput).
    pub fn build(self) -> crate::operation::check_access_not_granted::CheckAccessNotGrantedOutput {
        crate::operation::check_access_not_granted::CheckAccessNotGrantedOutput {
            result: self.result,
            message: self.message,
            reasons: self.reasons,
            _request_id: self._request_id,
        }
    }
}
