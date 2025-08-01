// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListContactChannelsOutput {
    /// <p>The pagination token to continue to the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of contact channels related to the specified contact.</p>
    pub contact_channels: ::std::vec::Vec<crate::types::ContactChannel>,
    _request_id: Option<String>,
}
impl ListContactChannelsOutput {
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of contact channels related to the specified contact.</p>
    pub fn contact_channels(&self) -> &[crate::types::ContactChannel] {
        use std::ops::Deref;
        self.contact_channels.deref()
    }
}
impl ::aws_types::request_id::RequestId for ListContactChannelsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListContactChannelsOutput {
    /// Creates a new builder-style object to manufacture [`ListContactChannelsOutput`](crate::operation::list_contact_channels::ListContactChannelsOutput).
    pub fn builder() -> crate::operation::list_contact_channels::builders::ListContactChannelsOutputBuilder {
        crate::operation::list_contact_channels::builders::ListContactChannelsOutputBuilder::default()
    }
}

/// A builder for [`ListContactChannelsOutput`](crate::operation::list_contact_channels::ListContactChannelsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListContactChannelsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) contact_channels: ::std::option::Option<::std::vec::Vec<crate::types::ContactChannel>>,
    _request_id: Option<String>,
}
impl ListContactChannelsOutputBuilder {
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `contact_channels`.
    ///
    /// To override the contents of this collection use [`set_contact_channels`](Self::set_contact_channels).
    ///
    /// <p>A list of contact channels related to the specified contact.</p>
    pub fn contact_channels(mut self, input: crate::types::ContactChannel) -> Self {
        let mut v = self.contact_channels.unwrap_or_default();
        v.push(input);
        self.contact_channels = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of contact channels related to the specified contact.</p>
    pub fn set_contact_channels(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ContactChannel>>) -> Self {
        self.contact_channels = input;
        self
    }
    /// <p>A list of contact channels related to the specified contact.</p>
    pub fn get_contact_channels(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ContactChannel>> {
        &self.contact_channels
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListContactChannelsOutput`](crate::operation::list_contact_channels::ListContactChannelsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`contact_channels`](crate::operation::list_contact_channels::builders::ListContactChannelsOutputBuilder::contact_channels)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_contact_channels::ListContactChannelsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_contact_channels::ListContactChannelsOutput {
            next_token: self.next_token,
            contact_channels: self.contact_channels.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "contact_channels",
                    "contact_channels was not specified but it is required when building ListContactChannelsOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
