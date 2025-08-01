// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelMulticastGroupSessionInput {
    /// <p>The ID of the multicast group.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl CancelMulticastGroupSessionInput {
    /// <p>The ID of the multicast group.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl CancelMulticastGroupSessionInput {
    /// Creates a new builder-style object to manufacture [`CancelMulticastGroupSessionInput`](crate::operation::cancel_multicast_group_session::CancelMulticastGroupSessionInput).
    pub fn builder() -> crate::operation::cancel_multicast_group_session::builders::CancelMulticastGroupSessionInputBuilder {
        crate::operation::cancel_multicast_group_session::builders::CancelMulticastGroupSessionInputBuilder::default()
    }
}

/// A builder for [`CancelMulticastGroupSessionInput`](crate::operation::cancel_multicast_group_session::CancelMulticastGroupSessionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelMulticastGroupSessionInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl CancelMulticastGroupSessionInputBuilder {
    /// <p>The ID of the multicast group.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the multicast group.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the multicast group.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`CancelMulticastGroupSessionInput`](crate::operation::cancel_multicast_group_session::CancelMulticastGroupSessionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::cancel_multicast_group_session::CancelMulticastGroupSessionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::cancel_multicast_group_session::CancelMulticastGroupSessionInput { id: self.id })
    }
}
