// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreatePortalOutput {
    /// <p>The ARN of the web portal.</p>
    pub portal_arn: ::std::string::String,
    /// <p>The endpoint URL of the web portal that users access in order to start streaming sessions.</p>
    pub portal_endpoint: ::std::string::String,
    _request_id: Option<String>,
}
impl CreatePortalOutput {
    /// <p>The ARN of the web portal.</p>
    pub fn portal_arn(&self) -> &str {
        use std::ops::Deref;
        self.portal_arn.deref()
    }
    /// <p>The endpoint URL of the web portal that users access in order to start streaming sessions.</p>
    pub fn portal_endpoint(&self) -> &str {
        use std::ops::Deref;
        self.portal_endpoint.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreatePortalOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreatePortalOutput {
    /// Creates a new builder-style object to manufacture [`CreatePortalOutput`](crate::operation::create_portal::CreatePortalOutput).
    pub fn builder() -> crate::operation::create_portal::builders::CreatePortalOutputBuilder {
        crate::operation::create_portal::builders::CreatePortalOutputBuilder::default()
    }
}

/// A builder for [`CreatePortalOutput`](crate::operation::create_portal::CreatePortalOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreatePortalOutputBuilder {
    pub(crate) portal_arn: ::std::option::Option<::std::string::String>,
    pub(crate) portal_endpoint: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreatePortalOutputBuilder {
    /// <p>The ARN of the web portal.</p>
    /// This field is required.
    pub fn portal_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.portal_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the web portal.</p>
    pub fn set_portal_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.portal_arn = input;
        self
    }
    /// <p>The ARN of the web portal.</p>
    pub fn get_portal_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.portal_arn
    }
    /// <p>The endpoint URL of the web portal that users access in order to start streaming sessions.</p>
    /// This field is required.
    pub fn portal_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.portal_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint URL of the web portal that users access in order to start streaming sessions.</p>
    pub fn set_portal_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.portal_endpoint = input;
        self
    }
    /// <p>The endpoint URL of the web portal that users access in order to start streaming sessions.</p>
    pub fn get_portal_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.portal_endpoint
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreatePortalOutput`](crate::operation::create_portal::CreatePortalOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`portal_arn`](crate::operation::create_portal::builders::CreatePortalOutputBuilder::portal_arn)
    /// - [`portal_endpoint`](crate::operation::create_portal::builders::CreatePortalOutputBuilder::portal_endpoint)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_portal::CreatePortalOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_portal::CreatePortalOutput {
            portal_arn: self.portal_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "portal_arn",
                    "portal_arn was not specified but it is required when building CreatePortalOutput",
                )
            })?,
            portal_endpoint: self.portal_endpoint.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "portal_endpoint",
                    "portal_endpoint was not specified but it is required when building CreatePortalOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
