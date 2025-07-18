// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAppInstanceBotOutput {
    /// <p>The detials of the <code>AppInstanceBot</code>.</p>
    pub app_instance_bot: ::std::option::Option<crate::types::AppInstanceBot>,
    _request_id: Option<String>,
}
impl DescribeAppInstanceBotOutput {
    /// <p>The detials of the <code>AppInstanceBot</code>.</p>
    pub fn app_instance_bot(&self) -> ::std::option::Option<&crate::types::AppInstanceBot> {
        self.app_instance_bot.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeAppInstanceBotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeAppInstanceBotOutput {
    /// Creates a new builder-style object to manufacture [`DescribeAppInstanceBotOutput`](crate::operation::describe_app_instance_bot::DescribeAppInstanceBotOutput).
    pub fn builder() -> crate::operation::describe_app_instance_bot::builders::DescribeAppInstanceBotOutputBuilder {
        crate::operation::describe_app_instance_bot::builders::DescribeAppInstanceBotOutputBuilder::default()
    }
}

/// A builder for [`DescribeAppInstanceBotOutput`](crate::operation::describe_app_instance_bot::DescribeAppInstanceBotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAppInstanceBotOutputBuilder {
    pub(crate) app_instance_bot: ::std::option::Option<crate::types::AppInstanceBot>,
    _request_id: Option<String>,
}
impl DescribeAppInstanceBotOutputBuilder {
    /// <p>The detials of the <code>AppInstanceBot</code>.</p>
    pub fn app_instance_bot(mut self, input: crate::types::AppInstanceBot) -> Self {
        self.app_instance_bot = ::std::option::Option::Some(input);
        self
    }
    /// <p>The detials of the <code>AppInstanceBot</code>.</p>
    pub fn set_app_instance_bot(mut self, input: ::std::option::Option<crate::types::AppInstanceBot>) -> Self {
        self.app_instance_bot = input;
        self
    }
    /// <p>The detials of the <code>AppInstanceBot</code>.</p>
    pub fn get_app_instance_bot(&self) -> &::std::option::Option<crate::types::AppInstanceBot> {
        &self.app_instance_bot
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeAppInstanceBotOutput`](crate::operation::describe_app_instance_bot::DescribeAppInstanceBotOutput).
    pub fn build(self) -> crate::operation::describe_app_instance_bot::DescribeAppInstanceBotOutput {
        crate::operation::describe_app_instance_bot::DescribeAppInstanceBotOutput {
            app_instance_bot: self.app_instance_bot,
            _request_id: self._request_id,
        }
    }
}
