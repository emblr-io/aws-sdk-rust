// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>ListVolumeInitiatorsOutput</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVolumeInitiatorsOutput {
    /// <p>The host names and port numbers of all iSCSI initiators that are connected to the gateway.</p>
    pub initiators: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl ListVolumeInitiatorsOutput {
    /// <p>The host names and port numbers of all iSCSI initiators that are connected to the gateway.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.initiators.is_none()`.
    pub fn initiators(&self) -> &[::std::string::String] {
        self.initiators.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListVolumeInitiatorsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListVolumeInitiatorsOutput {
    /// Creates a new builder-style object to manufacture [`ListVolumeInitiatorsOutput`](crate::operation::list_volume_initiators::ListVolumeInitiatorsOutput).
    pub fn builder() -> crate::operation::list_volume_initiators::builders::ListVolumeInitiatorsOutputBuilder {
        crate::operation::list_volume_initiators::builders::ListVolumeInitiatorsOutputBuilder::default()
    }
}

/// A builder for [`ListVolumeInitiatorsOutput`](crate::operation::list_volume_initiators::ListVolumeInitiatorsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListVolumeInitiatorsOutputBuilder {
    pub(crate) initiators: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl ListVolumeInitiatorsOutputBuilder {
    /// Appends an item to `initiators`.
    ///
    /// To override the contents of this collection use [`set_initiators`](Self::set_initiators).
    ///
    /// <p>The host names and port numbers of all iSCSI initiators that are connected to the gateway.</p>
    pub fn initiators(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.initiators.unwrap_or_default();
        v.push(input.into());
        self.initiators = ::std::option::Option::Some(v);
        self
    }
    /// <p>The host names and port numbers of all iSCSI initiators that are connected to the gateway.</p>
    pub fn set_initiators(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.initiators = input;
        self
    }
    /// <p>The host names and port numbers of all iSCSI initiators that are connected to the gateway.</p>
    pub fn get_initiators(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.initiators
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListVolumeInitiatorsOutput`](crate::operation::list_volume_initiators::ListVolumeInitiatorsOutput).
    pub fn build(self) -> crate::operation::list_volume_initiators::ListVolumeInitiatorsOutput {
        crate::operation::list_volume_initiators::ListVolumeInitiatorsOutput {
            initiators: self.initiators,
            _request_id: self._request_id,
        }
    }
}
