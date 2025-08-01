// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ListChannelModeratorsInput {
    /// <p>The ARN of the channel.</p>
    pub channel_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of moderators that you want returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token passed by previous API calls until all requested moderators are returned.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub chime_bearer: ::std::option::Option<::std::string::String>,
}
impl ListChannelModeratorsInput {
    /// <p>The ARN of the channel.</p>
    pub fn channel_arn(&self) -> ::std::option::Option<&str> {
        self.channel_arn.as_deref()
    }
    /// <p>The maximum number of moderators that you want returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token passed by previous API calls until all requested moderators are returned.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn chime_bearer(&self) -> ::std::option::Option<&str> {
        self.chime_bearer.as_deref()
    }
}
impl ::std::fmt::Debug for ListChannelModeratorsInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListChannelModeratorsInput");
        formatter.field("channel_arn", &self.channel_arn);
        formatter.field("max_results", &self.max_results);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("chime_bearer", &self.chime_bearer);
        formatter.finish()
    }
}
impl ListChannelModeratorsInput {
    /// Creates a new builder-style object to manufacture [`ListChannelModeratorsInput`](crate::operation::list_channel_moderators::ListChannelModeratorsInput).
    pub fn builder() -> crate::operation::list_channel_moderators::builders::ListChannelModeratorsInputBuilder {
        crate::operation::list_channel_moderators::builders::ListChannelModeratorsInputBuilder::default()
    }
}

/// A builder for [`ListChannelModeratorsInput`](crate::operation::list_channel_moderators::ListChannelModeratorsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ListChannelModeratorsInputBuilder {
    pub(crate) channel_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) chime_bearer: ::std::option::Option<::std::string::String>,
}
impl ListChannelModeratorsInputBuilder {
    /// <p>The ARN of the channel.</p>
    /// This field is required.
    pub fn channel_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.channel_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn set_channel_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.channel_arn = input;
        self
    }
    /// <p>The ARN of the channel.</p>
    pub fn get_channel_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.channel_arn
    }
    /// <p>The maximum number of moderators that you want returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of moderators that you want returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of moderators that you want returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token passed by previous API calls until all requested moderators are returned.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token passed by previous API calls until all requested moderators are returned.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token passed by previous API calls until all requested moderators are returned.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    /// This field is required.
    pub fn chime_bearer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.chime_bearer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn set_chime_bearer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.chime_bearer = input;
        self
    }
    /// <p>The ARN of the <code>AppInstanceUser</code> or <code>AppInstanceBot</code> that makes the API call.</p>
    pub fn get_chime_bearer(&self) -> &::std::option::Option<::std::string::String> {
        &self.chime_bearer
    }
    /// Consumes the builder and constructs a [`ListChannelModeratorsInput`](crate::operation::list_channel_moderators::ListChannelModeratorsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_channel_moderators::ListChannelModeratorsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_channel_moderators::ListChannelModeratorsInput {
            channel_arn: self.channel_arn,
            max_results: self.max_results,
            next_token: self.next_token,
            chime_bearer: self.chime_bearer,
        })
    }
}
impl ::std::fmt::Debug for ListChannelModeratorsInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListChannelModeratorsInputBuilder");
        formatter.field("channel_arn", &self.channel_arn);
        formatter.field("max_results", &self.max_results);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("chime_bearer", &self.chime_bearer);
        formatter.finish()
    }
}
