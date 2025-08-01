// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReleaseHostsInput {
    /// <p>The IDs of the Dedicated Hosts to release.</p>
    pub host_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ReleaseHostsInput {
    /// <p>The IDs of the Dedicated Hosts to release.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.host_ids.is_none()`.
    pub fn host_ids(&self) -> &[::std::string::String] {
        self.host_ids.as_deref().unwrap_or_default()
    }
}
impl ReleaseHostsInput {
    /// Creates a new builder-style object to manufacture [`ReleaseHostsInput`](crate::operation::release_hosts::ReleaseHostsInput).
    pub fn builder() -> crate::operation::release_hosts::builders::ReleaseHostsInputBuilder {
        crate::operation::release_hosts::builders::ReleaseHostsInputBuilder::default()
    }
}

/// A builder for [`ReleaseHostsInput`](crate::operation::release_hosts::ReleaseHostsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReleaseHostsInputBuilder {
    pub(crate) host_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ReleaseHostsInputBuilder {
    /// Appends an item to `host_ids`.
    ///
    /// To override the contents of this collection use [`set_host_ids`](Self::set_host_ids).
    ///
    /// <p>The IDs of the Dedicated Hosts to release.</p>
    pub fn host_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.host_ids.unwrap_or_default();
        v.push(input.into());
        self.host_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the Dedicated Hosts to release.</p>
    pub fn set_host_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.host_ids = input;
        self
    }
    /// <p>The IDs of the Dedicated Hosts to release.</p>
    pub fn get_host_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.host_ids
    }
    /// Consumes the builder and constructs a [`ReleaseHostsInput`](crate::operation::release_hosts::ReleaseHostsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::release_hosts::ReleaseHostsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::release_hosts::ReleaseHostsInput { host_ids: self.host_ids })
    }
}
