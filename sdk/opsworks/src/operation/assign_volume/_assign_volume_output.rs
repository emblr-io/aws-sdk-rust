// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssignVolumeOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssignVolumeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssignVolumeOutput {
    /// Creates a new builder-style object to manufacture [`AssignVolumeOutput`](crate::operation::assign_volume::AssignVolumeOutput).
    pub fn builder() -> crate::operation::assign_volume::builders::AssignVolumeOutputBuilder {
        crate::operation::assign_volume::builders::AssignVolumeOutputBuilder::default()
    }
}

/// A builder for [`AssignVolumeOutput`](crate::operation::assign_volume::AssignVolumeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssignVolumeOutputBuilder {
    _request_id: Option<String>,
}
impl AssignVolumeOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssignVolumeOutput`](crate::operation::assign_volume::AssignVolumeOutput).
    pub fn build(self) -> crate::operation::assign_volume::AssignVolumeOutput {
        crate::operation::assign_volume::AssignVolumeOutput {
            _request_id: self._request_id,
        }
    }
}
