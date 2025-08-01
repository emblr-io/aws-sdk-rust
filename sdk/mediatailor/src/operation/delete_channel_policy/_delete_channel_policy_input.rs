// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteChannelPolicyInput {
    /// <p>The name of the channel associated with this channel policy.</p>
    pub channel_name: ::std::option::Option<::std::string::String>,
}
impl DeleteChannelPolicyInput {
    /// <p>The name of the channel associated with this channel policy.</p>
    pub fn channel_name(&self) -> ::std::option::Option<&str> {
        self.channel_name.as_deref()
    }
}
impl DeleteChannelPolicyInput {
    /// Creates a new builder-style object to manufacture [`DeleteChannelPolicyInput`](crate::operation::delete_channel_policy::DeleteChannelPolicyInput).
    pub fn builder() -> crate::operation::delete_channel_policy::builders::DeleteChannelPolicyInputBuilder {
        crate::operation::delete_channel_policy::builders::DeleteChannelPolicyInputBuilder::default()
    }
}

/// A builder for [`DeleteChannelPolicyInput`](crate::operation::delete_channel_policy::DeleteChannelPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteChannelPolicyInputBuilder {
    pub(crate) channel_name: ::std::option::Option<::std::string::String>,
}
impl DeleteChannelPolicyInputBuilder {
    /// <p>The name of the channel associated with this channel policy.</p>
    /// This field is required.
    pub fn channel_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the channel associated with this channel policy.</p>
    pub fn set_channel_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_name = input;
        self
    }
    /// <p>The name of the channel associated with this channel policy.</p>
    pub fn get_channel_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_name
    }
    /// Consumes the builder and constructs a [`DeleteChannelPolicyInput`](crate::operation::delete_channel_policy::DeleteChannelPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_channel_policy::DeleteChannelPolicyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_channel_policy::DeleteChannelPolicyInput {
            channel_name: self.channel_name,
        })
    }
}
