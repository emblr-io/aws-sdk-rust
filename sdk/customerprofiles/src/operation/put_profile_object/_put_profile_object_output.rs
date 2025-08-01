// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutProfileObjectOutput {
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub profile_object_unique_key: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutProfileObjectOutput {
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn profile_object_unique_key(&self) -> ::std::option::Option<&str> {
        self.profile_object_unique_key.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for PutProfileObjectOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutProfileObjectOutput {
    /// Creates a new builder-style object to manufacture [`PutProfileObjectOutput`](crate::operation::put_profile_object::PutProfileObjectOutput).
    pub fn builder() -> crate::operation::put_profile_object::builders::PutProfileObjectOutputBuilder {
        crate::operation::put_profile_object::builders::PutProfileObjectOutputBuilder::default()
    }
}

/// A builder for [`PutProfileObjectOutput`](crate::operation::put_profile_object::PutProfileObjectOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutProfileObjectOutputBuilder {
    pub(crate) profile_object_unique_key: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutProfileObjectOutputBuilder {
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn profile_object_unique_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_object_unique_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn set_profile_object_unique_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_object_unique_key = input;
        self
    }
    /// <p>The unique identifier of the profile object generated by the service.</p>
    pub fn get_profile_object_unique_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_object_unique_key
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutProfileObjectOutput`](crate::operation::put_profile_object::PutProfileObjectOutput).
    pub fn build(self) -> crate::operation::put_profile_object::PutProfileObjectOutput {
        crate::operation::put_profile_object::PutProfileObjectOutput {
            profile_object_unique_key: self.profile_object_unique_key,
            _request_id: self._request_id,
        }
    }
}
