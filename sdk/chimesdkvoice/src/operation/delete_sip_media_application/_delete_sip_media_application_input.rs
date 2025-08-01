// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSipMediaApplicationInput {
    /// <p>The SIP media application ID.</p>
    pub sip_media_application_id: ::std::option::Option<::std::string::String>,
}
impl DeleteSipMediaApplicationInput {
    /// <p>The SIP media application ID.</p>
    pub fn sip_media_application_id(&self) -> ::std::option::Option<&str> {
        self.sip_media_application_id.as_deref()
    }
}
impl DeleteSipMediaApplicationInput {
    /// Creates a new builder-style object to manufacture [`DeleteSipMediaApplicationInput`](crate::operation::delete_sip_media_application::DeleteSipMediaApplicationInput).
    pub fn builder() -> crate::operation::delete_sip_media_application::builders::DeleteSipMediaApplicationInputBuilder {
        crate::operation::delete_sip_media_application::builders::DeleteSipMediaApplicationInputBuilder::default()
    }
}

/// A builder for [`DeleteSipMediaApplicationInput`](crate::operation::delete_sip_media_application::DeleteSipMediaApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSipMediaApplicationInputBuilder {
    pub(crate) sip_media_application_id: ::std::option::Option<::std::string::String>,
}
impl DeleteSipMediaApplicationInputBuilder {
    /// <p>The SIP media application ID.</p>
    /// This field is required.
    pub fn sip_media_application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sip_media_application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SIP media application ID.</p>
    pub fn set_sip_media_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sip_media_application_id = input;
        self
    }
    /// <p>The SIP media application ID.</p>
    pub fn get_sip_media_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sip_media_application_id
    }
    /// Consumes the builder and constructs a [`DeleteSipMediaApplicationInput`](crate::operation::delete_sip_media_application::DeleteSipMediaApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_sip_media_application::DeleteSipMediaApplicationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_sip_media_application::DeleteSipMediaApplicationInput {
            sip_media_application_id: self.sip_media_application_id,
        })
    }
}
