// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteStudioSessionMappingOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteStudioSessionMappingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteStudioSessionMappingOutput {
    /// Creates a new builder-style object to manufacture [`DeleteStudioSessionMappingOutput`](crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingOutput).
    pub fn builder() -> crate::operation::delete_studio_session_mapping::builders::DeleteStudioSessionMappingOutputBuilder {
        crate::operation::delete_studio_session_mapping::builders::DeleteStudioSessionMappingOutputBuilder::default()
    }
}

/// A builder for [`DeleteStudioSessionMappingOutput`](crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteStudioSessionMappingOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteStudioSessionMappingOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteStudioSessionMappingOutput`](crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingOutput).
    pub fn build(self) -> crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingOutput {
        crate::operation::delete_studio_session_mapping::DeleteStudioSessionMappingOutput {
            _request_id: self._request_id,
        }
    }
}
