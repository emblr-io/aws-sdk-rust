// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetComponentVersionArtifactOutput {
    /// <p>The URL of the artifact.</p>
    pub pre_signed_url: ::std::string::String,
    _request_id: Option<String>,
}
impl GetComponentVersionArtifactOutput {
    /// <p>The URL of the artifact.</p>
    pub fn pre_signed_url(&self) -> &str {
        use std::ops::Deref;
        self.pre_signed_url.deref()
    }
}
impl ::aws_types::request_id::RequestId for GetComponentVersionArtifactOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetComponentVersionArtifactOutput {
    /// Creates a new builder-style object to manufacture [`GetComponentVersionArtifactOutput`](crate::operation::get_component_version_artifact::GetComponentVersionArtifactOutput).
    pub fn builder() -> crate::operation::get_component_version_artifact::builders::GetComponentVersionArtifactOutputBuilder {
        crate::operation::get_component_version_artifact::builders::GetComponentVersionArtifactOutputBuilder::default()
    }
}

/// A builder for [`GetComponentVersionArtifactOutput`](crate::operation::get_component_version_artifact::GetComponentVersionArtifactOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetComponentVersionArtifactOutputBuilder {
    pub(crate) pre_signed_url: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetComponentVersionArtifactOutputBuilder {
    /// <p>The URL of the artifact.</p>
    /// This field is required.
    pub fn pre_signed_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pre_signed_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the artifact.</p>
    pub fn set_pre_signed_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pre_signed_url = input;
        self
    }
    /// <p>The URL of the artifact.</p>
    pub fn get_pre_signed_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.pre_signed_url
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetComponentVersionArtifactOutput`](crate::operation::get_component_version_artifact::GetComponentVersionArtifactOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`pre_signed_url`](crate::operation::get_component_version_artifact::builders::GetComponentVersionArtifactOutputBuilder::pre_signed_url)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_component_version_artifact::GetComponentVersionArtifactOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_component_version_artifact::GetComponentVersionArtifactOutput {
            pre_signed_url: self.pre_signed_url.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pre_signed_url",
                    "pre_signed_url was not specified but it is required when building GetComponentVersionArtifactOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
