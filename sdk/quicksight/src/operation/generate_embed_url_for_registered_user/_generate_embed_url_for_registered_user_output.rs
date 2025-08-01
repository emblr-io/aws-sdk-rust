// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GenerateEmbedUrlForRegisteredUserOutput {
    /// <p>The embed URL for the Amazon QuickSight dashboard, visual, Q search bar, Generative Q&amp;A experience, or console.</p>
    pub embed_url: ::std::string::String,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::string::String,
    _request_id: Option<String>,
}
impl GenerateEmbedUrlForRegisteredUserOutput {
    /// <p>The embed URL for the Amazon QuickSight dashboard, visual, Q search bar, Generative Q&amp;A experience, or console.</p>
    pub fn embed_url(&self) -> &str {
        use std::ops::Deref;
        self.embed_url.deref()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> &str {
        use std::ops::Deref;
        self.request_id.deref()
    }
}
impl ::std::fmt::Debug for GenerateEmbedUrlForRegisteredUserOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GenerateEmbedUrlForRegisteredUserOutput");
        formatter.field("embed_url", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("request_id", &self.request_id);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GenerateEmbedUrlForRegisteredUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GenerateEmbedUrlForRegisteredUserOutput {
    /// Creates a new builder-style object to manufacture [`GenerateEmbedUrlForRegisteredUserOutput`](crate::operation::generate_embed_url_for_registered_user::GenerateEmbedUrlForRegisteredUserOutput).
    pub fn builder() -> crate::operation::generate_embed_url_for_registered_user::builders::GenerateEmbedUrlForRegisteredUserOutputBuilder {
        crate::operation::generate_embed_url_for_registered_user::builders::GenerateEmbedUrlForRegisteredUserOutputBuilder::default()
    }
}

/// A builder for [`GenerateEmbedUrlForRegisteredUserOutput`](crate::operation::generate_embed_url_for_registered_user::GenerateEmbedUrlForRegisteredUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GenerateEmbedUrlForRegisteredUserOutputBuilder {
    pub(crate) embed_url: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<i32>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GenerateEmbedUrlForRegisteredUserOutputBuilder {
    /// <p>The embed URL for the Amazon QuickSight dashboard, visual, Q search bar, Generative Q&amp;A experience, or console.</p>
    /// This field is required.
    pub fn embed_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.embed_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The embed URL for the Amazon QuickSight dashboard, visual, Q search bar, Generative Q&amp;A experience, or console.</p>
    pub fn set_embed_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.embed_url = input;
        self
    }
    /// <p>The embed URL for the Amazon QuickSight dashboard, visual, Q search bar, Generative Q&amp;A experience, or console.</p>
    pub fn get_embed_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.embed_url
    }
    /// <p>The HTTP status of the request.</p>
    /// This field is required.
    pub fn status(mut self, input: i32) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<i32> {
        &self.status
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    /// This field is required.
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GenerateEmbedUrlForRegisteredUserOutput`](crate::operation::generate_embed_url_for_registered_user::GenerateEmbedUrlForRegisteredUserOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`embed_url`](crate::operation::generate_embed_url_for_registered_user::builders::GenerateEmbedUrlForRegisteredUserOutputBuilder::embed_url)
    /// - [`request_id`](crate::operation::generate_embed_url_for_registered_user::builders::GenerateEmbedUrlForRegisteredUserOutputBuilder::request_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::generate_embed_url_for_registered_user::GenerateEmbedUrlForRegisteredUserOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::generate_embed_url_for_registered_user::GenerateEmbedUrlForRegisteredUserOutput {
                embed_url: self.embed_url.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "embed_url",
                        "embed_url was not specified but it is required when building GenerateEmbedUrlForRegisteredUserOutput",
                    )
                })?,
                status: self.status.unwrap_or_default(),
                request_id: self.request_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "request_id",
                        "request_id was not specified but it is required when building GenerateEmbedUrlForRegisteredUserOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
impl ::std::fmt::Debug for GenerateEmbedUrlForRegisteredUserOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GenerateEmbedUrlForRegisteredUserOutputBuilder");
        formatter.field("embed_url", &"*** Sensitive Data Redacted ***");
        formatter.field("status", &self.status);
        formatter.field("request_id", &self.request_id);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
