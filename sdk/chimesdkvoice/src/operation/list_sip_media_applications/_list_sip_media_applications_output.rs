// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSipMediaApplicationsOutput {
    /// <p>The list of SIP media applications and application details.</p>
    pub sip_media_applications: ::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplication>>,
    /// <p>The token used to return the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSipMediaApplicationsOutput {
    /// <p>The list of SIP media applications and application details.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.sip_media_applications.is_none()`.
    pub fn sip_media_applications(&self) -> &[crate::types::SipMediaApplication] {
        self.sip_media_applications.as_deref().unwrap_or_default()
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSipMediaApplicationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSipMediaApplicationsOutput {
    /// Creates a new builder-style object to manufacture [`ListSipMediaApplicationsOutput`](crate::operation::list_sip_media_applications::ListSipMediaApplicationsOutput).
    pub fn builder() -> crate::operation::list_sip_media_applications::builders::ListSipMediaApplicationsOutputBuilder {
        crate::operation::list_sip_media_applications::builders::ListSipMediaApplicationsOutputBuilder::default()
    }
}

/// A builder for [`ListSipMediaApplicationsOutput`](crate::operation::list_sip_media_applications::ListSipMediaApplicationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSipMediaApplicationsOutputBuilder {
    pub(crate) sip_media_applications: ::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplication>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSipMediaApplicationsOutputBuilder {
    /// Appends an item to `sip_media_applications`.
    ///
    /// To override the contents of this collection use [`set_sip_media_applications`](Self::set_sip_media_applications).
    ///
    /// <p>The list of SIP media applications and application details.</p>
    pub fn sip_media_applications(mut self, input: crate::types::SipMediaApplication) -> Self {
        let mut v = self.sip_media_applications.unwrap_or_default();
        v.push(input);
        self.sip_media_applications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of SIP media applications and application details.</p>
    pub fn set_sip_media_applications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplication>>) -> Self {
        self.sip_media_applications = input;
        self
    }
    /// <p>The list of SIP media applications and application details.</p>
    pub fn get_sip_media_applications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SipMediaApplication>> {
        &self.sip_media_applications
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token used to return the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSipMediaApplicationsOutput`](crate::operation::list_sip_media_applications::ListSipMediaApplicationsOutput).
    pub fn build(self) -> crate::operation::list_sip_media_applications::ListSipMediaApplicationsOutput {
        crate::operation::list_sip_media_applications::ListSipMediaApplicationsOutput {
            sip_media_applications: self.sip_media_applications,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
