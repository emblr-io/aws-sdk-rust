// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSipMediaApplicationOutput {
    /// <p>The updated SIP media application’s details.</p>
    pub sip_media_application: ::std::option::Option<crate::types::SipMediaApplication>,
    _request_id: Option<String>,
}
impl UpdateSipMediaApplicationOutput {
    /// <p>The updated SIP media application’s details.</p>
    pub fn sip_media_application(&self) -> ::std::option::Option<&crate::types::SipMediaApplication> {
        self.sip_media_application.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateSipMediaApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateSipMediaApplicationOutput {
    /// Creates a new builder-style object to manufacture [`UpdateSipMediaApplicationOutput`](crate::operation::update_sip_media_application::UpdateSipMediaApplicationOutput).
    pub fn builder() -> crate::operation::update_sip_media_application::builders::UpdateSipMediaApplicationOutputBuilder {
        crate::operation::update_sip_media_application::builders::UpdateSipMediaApplicationOutputBuilder::default()
    }
}

/// A builder for [`UpdateSipMediaApplicationOutput`](crate::operation::update_sip_media_application::UpdateSipMediaApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSipMediaApplicationOutputBuilder {
    pub(crate) sip_media_application: ::std::option::Option<crate::types::SipMediaApplication>,
    _request_id: Option<String>,
}
impl UpdateSipMediaApplicationOutputBuilder {
    /// <p>The updated SIP media application’s details.</p>
    pub fn sip_media_application(mut self, input: crate::types::SipMediaApplication) -> Self {
        self.sip_media_application = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated SIP media application’s details.</p>
    pub fn set_sip_media_application(mut self, input: ::std::option::Option<crate::types::SipMediaApplication>) -> Self {
        self.sip_media_application = input;
        self
    }
    /// <p>The updated SIP media application’s details.</p>
    pub fn get_sip_media_application(&self) -> &::std::option::Option<crate::types::SipMediaApplication> {
        &self.sip_media_application
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateSipMediaApplicationOutput`](crate::operation::update_sip_media_application::UpdateSipMediaApplicationOutput).
    pub fn build(self) -> crate::operation::update_sip_media_application::UpdateSipMediaApplicationOutput {
        crate::operation::update_sip_media_application::UpdateSipMediaApplicationOutput {
            sip_media_application: self.sip_media_application,
            _request_id: self._request_id,
        }
    }
}
