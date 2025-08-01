// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartViewerSessionRevocationInput {
    /// <p>The ARN of the channel associated with the viewer session to revoke.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the viewer associated with the viewer session to revoke. Do not use this field for personally identifying, confidential, or sensitive information.</p>
    pub viewer_id: ::std::option::Option<::std::string::String>,
    /// <p>An optional filter on which versions of the viewer session to revoke. All versions less than or equal to the specified version will be revoked. Default: 0.</p>
    pub viewer_session_versions_less_than_or_equal_to: ::std::option::Option<i32>,
}
impl StartViewerSessionRevocationInput {
    /// <p>The ARN of the channel associated with the viewer session to revoke.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
    /// <p>The ID of the viewer associated with the viewer session to revoke. Do not use this field for personally identifying, confidential, or sensitive information.</p>
    pub fn viewer_id(&self) -> ::std::option::Option<&str> {
        self.viewer_id.as_deref()
    }
    /// <p>An optional filter on which versions of the viewer session to revoke. All versions less than or equal to the specified version will be revoked. Default: 0.</p>
    pub fn viewer_session_versions_less_than_or_equal_to(&self) -> ::std::option::Option<i32> {
        self.viewer_session_versions_less_than_or_equal_to
    }
}
impl StartViewerSessionRevocationInput {
    /// Creates a new builder-style object to manufacture [`StartViewerSessionRevocationInput`](crate::operation::start_viewer_session_revocation::StartViewerSessionRevocationInput).
    pub fn builder() -> crate::operation::start_viewer_session_revocation::builders::StartViewerSessionRevocationInputBuilder {
        crate::operation::start_viewer_session_revocation::builders::StartViewerSessionRevocationInputBuilder::default()
    }
}

/// A builder for [`StartViewerSessionRevocationInput`](crate::operation::start_viewer_session_revocation::StartViewerSessionRevocationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartViewerSessionRevocationInputBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) viewer_id: ::std::option::Option<::std::string::String>,
    pub(crate) viewer_session_versions_less_than_or_equal_to: ::std::option::Option<i32>,
}
impl StartViewerSessionRevocationInputBuilder {
    /// <p>The ARN of the channel associated with the viewer session to revoke.</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel associated with the viewer session to revoke.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>The ARN of the channel associated with the viewer session to revoke.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>The ID of the viewer associated with the viewer session to revoke. Do not use this field for personally identifying, confidential, or sensitive information.</p>
    /// This field is required.
    pub fn viewer_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.viewer_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the viewer associated with the viewer session to revoke. Do not use this field for personally identifying, confidential, or sensitive information.</p>
    pub fn set_viewer_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.viewer_id = input;
        self
    }
    /// <p>The ID of the viewer associated with the viewer session to revoke. Do not use this field for personally identifying, confidential, or sensitive information.</p>
    pub fn get_viewer_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.viewer_id
    }
    /// <p>An optional filter on which versions of the viewer session to revoke. All versions less than or equal to the specified version will be revoked. Default: 0.</p>
    pub fn viewer_session_versions_less_than_or_equal_to(mut self, input: i32) -> Self {
        self.viewer_session_versions_less_than_or_equal_to = ::std::option::Option::Some(input);
        self
    }
    /// <p>An optional filter on which versions of the viewer session to revoke. All versions less than or equal to the specified version will be revoked. Default: 0.</p>
    pub fn set_viewer_session_versions_less_than_or_equal_to(mut self, input: ::std::option::Option<i32>) -> Self {
        self.viewer_session_versions_less_than_or_equal_to = input;
        self
    }
    /// <p>An optional filter on which versions of the viewer session to revoke. All versions less than or equal to the specified version will be revoked. Default: 0.</p>
    pub fn get_viewer_session_versions_less_than_or_equal_to(&self) -> &::std::option::Option<i32> {
        &self.viewer_session_versions_less_than_or_equal_to
    }
    /// Consumes the builder and constructs a [`StartViewerSessionRevocationInput`](crate::operation::start_viewer_session_revocation::StartViewerSessionRevocationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_viewer_session_revocation::StartViewerSessionRevocationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_viewer_session_revocation::StartViewerSessionRevocationInput {
            channel_arn: self.channel_arn,
            viewer_id: self.viewer_id,
            viewer_session_versions_less_than_or_equal_to: self.viewer_session_versions_less_than_or_equal_to,
        })
    }
}
