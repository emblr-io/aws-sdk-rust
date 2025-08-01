// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListApplicationsOutput {
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of applications.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>An array of summary information on the configuration of one or more Amazon Q Business applications.</p>
    pub applications: ::std::option::Option<::std::vec::Vec<crate::types::Application>>,
    _request_id: Option<String>,
}
impl ListApplicationsOutput {
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of applications.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>An array of summary information on the configuration of one or more Amazon Q Business applications.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.applications.is_none()`.
    pub fn applications(&self) -> &[crate::types::Application] {
        self.applications.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListApplicationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListApplicationsOutput {
    /// Creates a new builder-style object to manufacture [`ListApplicationsOutput`](crate::operation::list_applications::ListApplicationsOutput).
    pub fn builder() -> crate::operation::list_applications::builders::ListApplicationsOutputBuilder {
        crate::operation::list_applications::builders::ListApplicationsOutputBuilder::default()
    }
}

/// A builder for [`ListApplicationsOutput`](crate::operation::list_applications::ListApplicationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListApplicationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) applications: ::std::option::Option<::std::vec::Vec<crate::types::Application>>,
    _request_id: Option<String>,
}
impl ListApplicationsOutputBuilder {
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of applications.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of applications.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, Amazon Q Business returns this token. You can use this token in a subsequent request to retrieve the next set of applications.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `applications`.
    ///
    /// To override the contents of this collection use [`set_applications`](Self::set_applications).
    ///
    /// <p>An array of summary information on the configuration of one or more Amazon Q Business applications.</p>
    pub fn applications(mut self, input: crate::types::Application) -> Self {
        let mut v = self.applications.unwrap_or_default();
        v.push(input);
        self.applications = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of summary information on the configuration of one or more Amazon Q Business applications.</p>
    pub fn set_applications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Application>>) -> Self {
        self.applications = input;
        self
    }
    /// <p>An array of summary information on the configuration of one or more Amazon Q Business applications.</p>
    pub fn get_applications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Application>> {
        &self.applications
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListApplicationsOutput`](crate::operation::list_applications::ListApplicationsOutput).
    pub fn build(self) -> crate::operation::list_applications::ListApplicationsOutput {
        crate::operation::list_applications::ListApplicationsOutput {
            next_token: self.next_token,
            applications: self.applications,
            _request_id: self._request_id,
        }
    }
}
