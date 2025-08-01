// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateVolumeOutput {
    /// <p>A description of the volume just updated. Returned after a successful <code>UpdateVolume</code> API operation.</p>
    pub volume: ::std::option::Option<crate::types::Volume>,
    _request_id: Option<String>,
}
impl UpdateVolumeOutput {
    /// <p>A description of the volume just updated. Returned after a successful <code>UpdateVolume</code> API operation.</p>
    pub fn volume(&self) -> ::std::option::Option<&crate::types::Volume> {
        self.volume.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateVolumeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateVolumeOutput {
    /// Creates a new builder-style object to manufacture [`UpdateVolumeOutput`](crate::operation::update_volume::UpdateVolumeOutput).
    pub fn builder() -> crate::operation::update_volume::builders::UpdateVolumeOutputBuilder {
        crate::operation::update_volume::builders::UpdateVolumeOutputBuilder::default()
    }
}

/// A builder for [`UpdateVolumeOutput`](crate::operation::update_volume::UpdateVolumeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateVolumeOutputBuilder {
    pub(crate) volume: ::std::option::Option<crate::types::Volume>,
    _request_id: Option<String>,
}
impl UpdateVolumeOutputBuilder {
    /// <p>A description of the volume just updated. Returned after a successful <code>UpdateVolume</code> API operation.</p>
    pub fn volume(mut self, input: crate::types::Volume) -> Self {
        self.volume = ::std::option::Option::Some(input);
        self
    }
    /// <p>A description of the volume just updated. Returned after a successful <code>UpdateVolume</code> API operation.</p>
    pub fn set_volume(mut self, input: ::std::option::Option<crate::types::Volume>) -> Self {
        self.volume = input;
        self
    }
    /// <p>A description of the volume just updated. Returned after a successful <code>UpdateVolume</code> API operation.</p>
    pub fn get_volume(&self) -> &::std::option::Option<crate::types::Volume> {
        &self.volume
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateVolumeOutput`](crate::operation::update_volume::UpdateVolumeOutput).
    pub fn build(self) -> crate::operation::update_volume::UpdateVolumeOutput {
        crate::operation::update_volume::UpdateVolumeOutput {
            volume: self.volume,
            _request_id: self._request_id,
        }
    }
}
