// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeChannelModeratedByAppInstanceUserOutput {
    /// <p>The moderated channel.</p>
    pub channel: ::std::option::Option<crate::types::ChannelModeratedByAppInstanceUserSummary>,
    _request_id: Option<String>,
}
impl DescribeChannelModeratedByAppInstanceUserOutput {
    /// <p>The moderated channel.</p>
    pub fn channel(&self) -> ::std::option::Option<&crate::types::ChannelModeratedByAppInstanceUserSummary> {
        self.channel.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeChannelModeratedByAppInstanceUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeChannelModeratedByAppInstanceUserOutput {
    /// Creates a new builder-style object to manufacture [`DescribeChannelModeratedByAppInstanceUserOutput`](crate::operation::describe_channel_moderated_by_app_instance_user::DescribeChannelModeratedByAppInstanceUserOutput).
    pub fn builder(
    ) -> crate::operation::describe_channel_moderated_by_app_instance_user::builders::DescribeChannelModeratedByAppInstanceUserOutputBuilder {
        crate::operation::describe_channel_moderated_by_app_instance_user::builders::DescribeChannelModeratedByAppInstanceUserOutputBuilder::default()
    }
}

/// A builder for [`DescribeChannelModeratedByAppInstanceUserOutput`](crate::operation::describe_channel_moderated_by_app_instance_user::DescribeChannelModeratedByAppInstanceUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeChannelModeratedByAppInstanceUserOutputBuilder {
    pub(crate) channel: ::std::option::Option<crate::types::ChannelModeratedByAppInstanceUserSummary>,
    _request_id: Option<String>,
}
impl DescribeChannelModeratedByAppInstanceUserOutputBuilder {
    /// <p>The moderated channel.</p>
    pub fn channel(mut self, input: crate::types::ChannelModeratedByAppInstanceUserSummary) -> Self {
        self.channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The moderated channel.</p>
    pub fn set_channel(mut self, input: ::std::option::Option<crate::types::ChannelModeratedByAppInstanceUserSummary>) -> Self {
        self.channel = input;
        self
    }
    /// <p>The moderated channel.</p>
    pub fn get_channel(&self) -> &::std::option::Option<crate::types::ChannelModeratedByAppInstanceUserSummary> {
        &self.channel
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeChannelModeratedByAppInstanceUserOutput`](crate::operation::describe_channel_moderated_by_app_instance_user::DescribeChannelModeratedByAppInstanceUserOutput).
    pub fn build(self) -> crate::operation::describe_channel_moderated_by_app_instance_user::DescribeChannelModeratedByAppInstanceUserOutput {
        crate::operation::describe_channel_moderated_by_app_instance_user::DescribeChannelModeratedByAppInstanceUserOutput {
            channel: self.channel,
            _request_id: self._request_id,
        }
    }
}
