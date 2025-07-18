// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReleaseHostsOutput {
    /// <p>The IDs of the Dedicated Hosts that were successfully released.</p>
    pub successful: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The IDs of the Dedicated Hosts that could not be released, including an error message.</p>
    pub unsuccessful: ::std::option::Option<::std::vec::Vec<crate::types::UnsuccessfulItem>>,
    _request_id: Option<String>,
}
impl ReleaseHostsOutput {
    /// <p>The IDs of the Dedicated Hosts that were successfully released.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.successful.is_none()`.
    pub fn successful(&self) -> &[::std::string::String] {
        self.successful.as_deref().unwrap_or_default()
    }
    /// <p>The IDs of the Dedicated Hosts that could not be released, including an error message.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unsuccessful.is_none()`.
    pub fn unsuccessful(&self) -> &[crate::types::UnsuccessfulItem] {
        self.unsuccessful.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ReleaseHostsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReleaseHostsOutput {
    /// Creates a new builder-style object to manufacture [`ReleaseHostsOutput`](crate::operation::release_hosts::ReleaseHostsOutput).
    pub fn builder() -> crate::operation::release_hosts::builders::ReleaseHostsOutputBuilder {
        crate::operation::release_hosts::builders::ReleaseHostsOutputBuilder::default()
    }
}

/// A builder for [`ReleaseHostsOutput`](crate::operation::release_hosts::ReleaseHostsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReleaseHostsOutputBuilder {
    pub(crate) successful: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) unsuccessful: ::std::option::Option<::std::vec::Vec<crate::types::UnsuccessfulItem>>,
    _request_id: Option<String>,
}
impl ReleaseHostsOutputBuilder {
    /// Appends an item to `successful`.
    ///
    /// To override the contents of this collection use [`set_successful`](Self::set_successful).
    ///
    /// <p>The IDs of the Dedicated Hosts that were successfully released.</p>
    pub fn successful(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.successful.unwrap_or_default();
        v.push(input.into());
        self.successful = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the Dedicated Hosts that were successfully released.</p>
    pub fn set_successful(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.successful = input;
        self
    }
    /// <p>The IDs of the Dedicated Hosts that were successfully released.</p>
    pub fn get_successful(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.successful
    }
    /// Appends an item to `unsuccessful`.
    ///
    /// To override the contents of this collection use [`set_unsuccessful`](Self::set_unsuccessful).
    ///
    /// <p>The IDs of the Dedicated Hosts that could not be released, including an error message.</p>
    pub fn unsuccessful(mut self, input: crate::types::UnsuccessfulItem) -> Self {
        let mut v = self.unsuccessful.unwrap_or_default();
        v.push(input);
        self.unsuccessful = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the Dedicated Hosts that could not be released, including an error message.</p>
    pub fn set_unsuccessful(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UnsuccessfulItem>>) -> Self {
        self.unsuccessful = input;
        self
    }
    /// <p>The IDs of the Dedicated Hosts that could not be released, including an error message.</p>
    pub fn get_unsuccessful(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnsuccessfulItem>> {
        &self.unsuccessful
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReleaseHostsOutput`](crate::operation::release_hosts::ReleaseHostsOutput).
    pub fn build(self) -> crate::operation::release_hosts::ReleaseHostsOutput {
        crate::operation::release_hosts::ReleaseHostsOutput {
            successful: self.successful,
            unsuccessful: self.unsuccessful,
            _request_id: self._request_id,
        }
    }
}
