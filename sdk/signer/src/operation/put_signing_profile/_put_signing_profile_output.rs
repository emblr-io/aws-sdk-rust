// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutSigningProfileOutput {
    /// <p>The Amazon Resource Name (ARN) of the signing profile created.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The version of the signing profile being created.</p>
    pub profile_version: ::std::option::Option<::std::string::String>,
    /// <p>The signing profile ARN, including the profile version.</p>
    pub profile_version_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutSigningProfileOutput {
    /// <p>The Amazon Resource Name (ARN) of the signing profile created.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The version of the signing profile being created.</p>
    pub fn profile_version(&self) -> ::std::option::Option<&str> {
        self.profile_version.as_deref()
    }
    /// <p>The signing profile ARN, including the profile version.</p>
    pub fn profile_version_arn(&self) -> ::std::option::Option<&str> {
        self.profile_version_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for PutSigningProfileOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutSigningProfileOutput {
    /// Creates a new builder-style object to manufacture [`PutSigningProfileOutput`](crate::operation::put_signing_profile::PutSigningProfileOutput).
    pub fn builder() -> crate::operation::put_signing_profile::builders::PutSigningProfileOutputBuilder {
        crate::operation::put_signing_profile::builders::PutSigningProfileOutputBuilder::default()
    }
}

/// A builder for [`PutSigningProfileOutput`](crate::operation::put_signing_profile::PutSigningProfileOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutSigningProfileOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) profile_version: ::std::option::Option<::std::string::String>,
    pub(crate) profile_version_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutSigningProfileOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the signing profile created.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the signing profile created.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the signing profile created.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The version of the signing profile being created.</p>
    pub fn profile_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the signing profile being created.</p>
    pub fn set_profile_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_version = input;
        self
    }
    /// <p>The version of the signing profile being created.</p>
    pub fn get_profile_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_version
    }
    /// <p>The signing profile ARN, including the profile version.</p>
    pub fn profile_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profile_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The signing profile ARN, including the profile version.</p>
    pub fn set_profile_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profile_version_arn = input;
        self
    }
    /// <p>The signing profile ARN, including the profile version.</p>
    pub fn get_profile_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.profile_version_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutSigningProfileOutput`](crate::operation::put_signing_profile::PutSigningProfileOutput).
    pub fn build(self) -> crate::operation::put_signing_profile::PutSigningProfileOutput {
        crate::operation::put_signing_profile::PutSigningProfileOutput {
            arn: self.arn,
            profile_version: self.profile_version,
            profile_version_arn: self.profile_version_arn,
            _request_id: self._request_id,
        }
    }
}
