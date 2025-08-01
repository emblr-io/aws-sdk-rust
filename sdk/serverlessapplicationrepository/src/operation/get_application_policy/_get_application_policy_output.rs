// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetApplicationPolicyOutput {
    /// <p>An array of policy statements applied to the application.</p>
    pub statements: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationPolicyStatement>>,
    _request_id: Option<String>,
}
impl GetApplicationPolicyOutput {
    /// <p>An array of policy statements applied to the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.statements.is_none()`.
    pub fn statements(&self) -> &[crate::types::ApplicationPolicyStatement] {
        self.statements.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for GetApplicationPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetApplicationPolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetApplicationPolicyOutput`](crate::operation::get_application_policy::GetApplicationPolicyOutput).
    pub fn builder() -> crate::operation::get_application_policy::builders::GetApplicationPolicyOutputBuilder {
        crate::operation::get_application_policy::builders::GetApplicationPolicyOutputBuilder::default()
    }
}

/// A builder for [`GetApplicationPolicyOutput`](crate::operation::get_application_policy::GetApplicationPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetApplicationPolicyOutputBuilder {
    pub(crate) statements: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationPolicyStatement>>,
    _request_id: Option<String>,
}
impl GetApplicationPolicyOutputBuilder {
    /// Appends an item to `statements`.
    ///
    /// To override the contents of this collection use [`set_statements`](Self::set_statements).
    ///
    /// <p>An array of policy statements applied to the application.</p>
    pub fn statements(mut self, input: crate::types::ApplicationPolicyStatement) -> Self {
        let mut v = self.statements.unwrap_or_default();
        v.push(input);
        self.statements = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of policy statements applied to the application.</p>
    pub fn set_statements(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ApplicationPolicyStatement>>) -> Self {
        self.statements = input;
        self
    }
    /// <p>An array of policy statements applied to the application.</p>
    pub fn get_statements(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ApplicationPolicyStatement>> {
        &self.statements
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetApplicationPolicyOutput`](crate::operation::get_application_policy::GetApplicationPolicyOutput).
    pub fn build(self) -> crate::operation::get_application_policy::GetApplicationPolicyOutput {
        crate::operation::get_application_policy::GetApplicationPolicyOutput {
            statements: self.statements,
            _request_id: self._request_id,
        }
    }
}
