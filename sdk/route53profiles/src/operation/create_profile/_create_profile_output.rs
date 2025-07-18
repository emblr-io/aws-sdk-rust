// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateProfileOutput {
    /// <p>The Profile that you just created.</p>
    pub profile: ::std::option::Option<crate::types::Profile>,
    _request_id: Option<String>,
}
impl CreateProfileOutput {
    /// <p>The Profile that you just created.</p>
    pub fn profile(&self) -> ::std::option::Option<&crate::types::Profile> {
        self.profile.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateProfileOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateProfileOutput {
    /// Creates a new builder-style object to manufacture [`CreateProfileOutput`](crate::operation::create_profile::CreateProfileOutput).
    pub fn builder() -> crate::operation::create_profile::builders::CreateProfileOutputBuilder {
        crate::operation::create_profile::builders::CreateProfileOutputBuilder::default()
    }
}

/// A builder for [`CreateProfileOutput`](crate::operation::create_profile::CreateProfileOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateProfileOutputBuilder {
    pub(crate) profile: ::std::option::Option<crate::types::Profile>,
    _request_id: Option<String>,
}
impl CreateProfileOutputBuilder {
    /// <p>The Profile that you just created.</p>
    pub fn profile(mut self, input: crate::types::Profile) -> Self {
        self.profile = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Profile that you just created.</p>
    pub fn set_profile(mut self, input: ::std::option::Option<crate::types::Profile>) -> Self {
        self.profile = input;
        self
    }
    /// <p>The Profile that you just created.</p>
    pub fn get_profile(&self) -> &::std::option::Option<crate::types::Profile> {
        &self.profile
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateProfileOutput`](crate::operation::create_profile::CreateProfileOutput).
    pub fn build(self) -> crate::operation::create_profile::CreateProfileOutput {
        crate::operation::create_profile::CreateProfileOutput {
            profile: self.profile,
            _request_id: self._request_id,
        }
    }
}
