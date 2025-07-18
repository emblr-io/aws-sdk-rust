// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteApnsSandboxChannelInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
}
impl DeleteApnsSandboxChannelInput {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
}
impl DeleteApnsSandboxChannelInput {
    /// Creates a new builder-style object to manufacture [`DeleteApnsSandboxChannelInput`](crate::operation::delete_apns_sandbox_channel::DeleteApnsSandboxChannelInput).
    pub fn builder() -> crate::operation::delete_apns_sandbox_channel::builders::DeleteApnsSandboxChannelInputBuilder {
        crate::operation::delete_apns_sandbox_channel::builders::DeleteApnsSandboxChannelInputBuilder::default()
    }
}

/// A builder for [`DeleteApnsSandboxChannelInput`](crate::operation::delete_apns_sandbox_channel::DeleteApnsSandboxChannelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteApnsSandboxChannelInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
}
impl DeleteApnsSandboxChannelInputBuilder {
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The unique identifier for the application. This identifier is displayed as the <b>Project ID</b> on the Amazon Pinpoint console.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// Consumes the builder and constructs a [`DeleteApnsSandboxChannelInput`](crate::operation::delete_apns_sandbox_channel::DeleteApnsSandboxChannelInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_apns_sandbox_channel::DeleteApnsSandboxChannelInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_apns_sandbox_channel::DeleteApnsSandboxChannelInput {
            application_id: self.application_id,
        })
    }
}
