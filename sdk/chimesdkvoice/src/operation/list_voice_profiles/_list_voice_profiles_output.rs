// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVoiceProfilesOutput {
    /// <p>The list of voice profiles.</p>
    pub voice_profiles: ::std::option::Option<::std::vec::Vec<crate::types::VoiceProfileSummary>>,
    /// <p>The token used to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListVoiceProfilesOutput {
    /// <p>The list of voice profiles.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.voice_profiles.is_none()`.
    pub fn voice_profiles(&self) -> &[crate::types::VoiceProfileSummary] {
        self.voice_profiles.as_deref().unwrap_or_default()
    }
    /// <p>The token used to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListVoiceProfilesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListVoiceProfilesOutput {
    /// Creates a new builder-style object to manufacture [`ListVoiceProfilesOutput`](crate::operation::list_voice_profiles::ListVoiceProfilesOutput).
    pub fn builder() -> crate::operation::list_voice_profiles::builders::ListVoiceProfilesOutputBuilder {
        crate::operation::list_voice_profiles::builders::ListVoiceProfilesOutputBuilder::default()
    }
}

/// A builder for [`ListVoiceProfilesOutput`](crate::operation::list_voice_profiles::ListVoiceProfilesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListVoiceProfilesOutputBuilder {
    pub(crate) voice_profiles: ::std::option::Option<::std::vec::Vec<crate::types::VoiceProfileSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListVoiceProfilesOutputBuilder {
    /// Appends an item to `voice_profiles`.
    ///
    /// To override the contents of this collection use [`set_voice_profiles`](Self::set_voice_profiles).
    ///
    /// <p>The list of voice profiles.</p>
    pub fn voice_profiles(mut self, input: crate::types::VoiceProfileSummary) -> Self {
        let mut v = self.voice_profiles.unwrap_or_default();
        v.push(input);
        self.voice_profiles = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of voice profiles.</p>
    pub fn set_voice_profiles(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VoiceProfileSummary>>) -> Self {
        self.voice_profiles = input;
        self
    }
    /// <p>The list of voice profiles.</p>
    pub fn get_voice_profiles(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VoiceProfileSummary>> {
        &self.voice_profiles
    }
    /// <p>The token used to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token used to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token used to retrieve the next page of results.</p>
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
    /// Consumes the builder and constructs a [`ListVoiceProfilesOutput`](crate::operation::list_voice_profiles::ListVoiceProfilesOutput).
    pub fn build(self) -> crate::operation::list_voice_profiles::ListVoiceProfilesOutput {
        crate::operation::list_voice_profiles::ListVoiceProfilesOutput {
            voice_profiles: self.voice_profiles,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
