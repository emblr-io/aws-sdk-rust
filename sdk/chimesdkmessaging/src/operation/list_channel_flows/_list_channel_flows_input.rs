// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ListChannelFlowsInput {
    /// <p>The ARN of the app instance.</p>
    pub app_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of channel flows that you want to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token passed by previous API calls until all requested channel flows are returned.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListChannelFlowsInput {
    /// <p>The ARN of the app instance.</p>
    pub fn app_instance_arn(&self) -> ::std::option::Option<&str> {
        self.app_instance_arn.as_deref()
    }
    /// <p>The maximum number of channel flows that you want to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token passed by previous API calls until all requested channel flows are returned.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::std::fmt::Debug for ListChannelFlowsInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListChannelFlowsInput");
        formatter.field("app_instance_arn", &self.app_instance_arn);
        formatter.field("max_results", &self.max_results);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl ListChannelFlowsInput {
    /// Creates a new builder-style object to manufacture [`ListChannelFlowsInput`](crate::operation::list_channel_flows::ListChannelFlowsInput).
    pub fn builder() -> crate::operation::list_channel_flows::builders::ListChannelFlowsInputBuilder {
        crate::operation::list_channel_flows::builders::ListChannelFlowsInputBuilder::default()
    }
}

/// A builder for [`ListChannelFlowsInput`](crate::operation::list_channel_flows::ListChannelFlowsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ListChannelFlowsInputBuilder {
    pub(crate) app_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListChannelFlowsInputBuilder {
    /// <p>The ARN of the app instance.</p>
    /// This field is required.
    pub fn app_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the app instance.</p>
    pub fn set_app_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_instance_arn = input;
        self
    }
    /// <p>The ARN of the app instance.</p>
    pub fn get_app_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_instance_arn
    }
    /// <p>The maximum number of channel flows that you want to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of channel flows that you want to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of channel flows that you want to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token passed by previous API calls until all requested channel flows are returned.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token passed by previous API calls until all requested channel flows are returned.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token passed by previous API calls until all requested channel flows are returned.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListChannelFlowsInput`](crate::operation::list_channel_flows::ListChannelFlowsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_channel_flows::ListChannelFlowsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_channel_flows::ListChannelFlowsInput {
            app_instance_arn: self.app_instance_arn,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
impl ::std::fmt::Debug for ListChannelFlowsInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListChannelFlowsInputBuilder");
        formatter.field("app_instance_arn", &self.app_instance_arn);
        formatter.field("max_results", &self.max_results);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
