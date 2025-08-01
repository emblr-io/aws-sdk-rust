// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateFaceLivenessSessionOutput {
    /// <p>A unique 128-bit UUID identifying a Face Liveness session. A new sessionID must be used for every Face Liveness check. If a given sessionID is used for subsequent Face Liveness checks, the checks will fail. Additionally, a SessionId expires 3 minutes after it's sent, making all Liveness data associated with the session (e.g., sessionID, reference image, audit images, etc.) unavailable.</p>
    pub session_id: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateFaceLivenessSessionOutput {
    /// <p>A unique 128-bit UUID identifying a Face Liveness session. A new sessionID must be used for every Face Liveness check. If a given sessionID is used for subsequent Face Liveness checks, the checks will fail. Additionally, a SessionId expires 3 minutes after it's sent, making all Liveness data associated with the session (e.g., sessionID, reference image, audit images, etc.) unavailable.</p>
    pub fn session_id(&self) -> &str {
        use std::ops::Deref;
        self.session_id.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateFaceLivenessSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateFaceLivenessSessionOutput {
    /// Creates a new builder-style object to manufacture [`CreateFaceLivenessSessionOutput`](crate::operation::create_face_liveness_session::CreateFaceLivenessSessionOutput).
    pub fn builder() -> crate::operation::create_face_liveness_session::builders::CreateFaceLivenessSessionOutputBuilder {
        crate::operation::create_face_liveness_session::builders::CreateFaceLivenessSessionOutputBuilder::default()
    }
}

/// A builder for [`CreateFaceLivenessSessionOutput`](crate::operation::create_face_liveness_session::CreateFaceLivenessSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateFaceLivenessSessionOutputBuilder {
    pub(crate) session_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateFaceLivenessSessionOutputBuilder {
    /// <p>A unique 128-bit UUID identifying a Face Liveness session. A new sessionID must be used for every Face Liveness check. If a given sessionID is used for subsequent Face Liveness checks, the checks will fail. Additionally, a SessionId expires 3 minutes after it's sent, making all Liveness data associated with the session (e.g., sessionID, reference image, audit images, etc.) unavailable.</p>
    /// This field is required.
    pub fn session_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.session_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique 128-bit UUID identifying a Face Liveness session. A new sessionID must be used for every Face Liveness check. If a given sessionID is used for subsequent Face Liveness checks, the checks will fail. Additionally, a SessionId expires 3 minutes after it's sent, making all Liveness data associated with the session (e.g., sessionID, reference image, audit images, etc.) unavailable.</p>
    pub fn set_session_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.session_id = input;
        self
    }
    /// <p>A unique 128-bit UUID identifying a Face Liveness session. A new sessionID must be used for every Face Liveness check. If a given sessionID is used for subsequent Face Liveness checks, the checks will fail. Additionally, a SessionId expires 3 minutes after it's sent, making all Liveness data associated with the session (e.g., sessionID, reference image, audit images, etc.) unavailable.</p>
    pub fn get_session_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.session_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateFaceLivenessSessionOutput`](crate::operation::create_face_liveness_session::CreateFaceLivenessSessionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`session_id`](crate::operation::create_face_liveness_session::builders::CreateFaceLivenessSessionOutputBuilder::session_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_face_liveness_session::CreateFaceLivenessSessionOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_face_liveness_session::CreateFaceLivenessSessionOutput {
            session_id: self.session_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "session_id",
                    "session_id was not specified but it is required when building CreateFaceLivenessSessionOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
