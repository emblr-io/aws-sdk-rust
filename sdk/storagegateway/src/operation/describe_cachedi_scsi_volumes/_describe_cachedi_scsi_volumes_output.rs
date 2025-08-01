// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON object containing the following fields:</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCachediScsiVolumesOutput {
    /// <p>An array of objects where each object contains metadata about one cached volume.</p>
    pub cachedi_scsi_volumes: ::std::option::Option<::std::vec::Vec<crate::types::CachediScsiVolume>>,
    _request_id: Option<String>,
}
impl DescribeCachediScsiVolumesOutput {
    /// <p>An array of objects where each object contains metadata about one cached volume.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cachedi_scsi_volumes.is_none()`.
    pub fn cachedi_scsi_volumes(&self) -> &[crate::types::CachediScsiVolume] {
        self.cachedi_scsi_volumes.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCachediScsiVolumesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCachediScsiVolumesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCachediScsiVolumesOutput`](crate::operation::describe_cachedi_scsi_volumes::DescribeCachediScsiVolumesOutput).
    pub fn builder() -> crate::operation::describe_cachedi_scsi_volumes::builders::DescribeCachediScsiVolumesOutputBuilder {
        crate::operation::describe_cachedi_scsi_volumes::builders::DescribeCachediScsiVolumesOutputBuilder::default()
    }
}

/// A builder for [`DescribeCachediScsiVolumesOutput`](crate::operation::describe_cachedi_scsi_volumes::DescribeCachediScsiVolumesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCachediScsiVolumesOutputBuilder {
    pub(crate) cachedi_scsi_volumes: ::std::option::Option<::std::vec::Vec<crate::types::CachediScsiVolume>>,
    _request_id: Option<String>,
}
impl DescribeCachediScsiVolumesOutputBuilder {
    /// Appends an item to `cachedi_scsi_volumes`.
    ///
    /// To override the contents of this collection use [`set_cachedi_scsi_volumes`](Self::set_cachedi_scsi_volumes).
    ///
    /// <p>An array of objects where each object contains metadata about one cached volume.</p>
    pub fn cachedi_scsi_volumes(mut self, input: crate::types::CachediScsiVolume) -> Self {
        let mut v = self.cachedi_scsi_volumes.unwrap_or_default();
        v.push(input);
        self.cachedi_scsi_volumes = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects where each object contains metadata about one cached volume.</p>
    pub fn set_cachedi_scsi_volumes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CachediScsiVolume>>) -> Self {
        self.cachedi_scsi_volumes = input;
        self
    }
    /// <p>An array of objects where each object contains metadata about one cached volume.</p>
    pub fn get_cachedi_scsi_volumes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CachediScsiVolume>> {
        &self.cachedi_scsi_volumes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCachediScsiVolumesOutput`](crate::operation::describe_cachedi_scsi_volumes::DescribeCachediScsiVolumesOutput).
    pub fn build(self) -> crate::operation::describe_cachedi_scsi_volumes::DescribeCachediScsiVolumesOutput {
        crate::operation::describe_cachedi_scsi_volumes::DescribeCachediScsiVolumesOutput {
            cachedi_scsi_volumes: self.cachedi_scsi_volumes,
            _request_id: self._request_id,
        }
    }
}
