// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ListAppInstanceBotsOutput {
    /// <p>The ARN of the AppInstance.</p>
    pub app_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The information for each requested <code>AppInstanceBot</code>.</p>
    pub app_instance_bots: ::std::option::Option<::std::vec::Vec<crate::types::AppInstanceBotSummary>>,
    /// <p>The token passed by previous API calls until all requested bots are returned.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAppInstanceBotsOutput {
    /// <p>The ARN of the AppInstance.</p>
    pub fn app_instance_arn(&self) -> ::std::option::Option<&str> {
        self.app_instance_arn.as_deref()
    }
    /// <p>The information for each requested <code>AppInstanceBot</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.app_instance_bots.is_none()`.
    pub fn app_instance_bots(&self) -> &[crate::types::AppInstanceBotSummary] {
        self.app_instance_bots.as_deref().unwrap_or_default()
    }
    /// <p>The token passed by previous API calls until all requested bots are returned.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::std::fmt::Debug for ListAppInstanceBotsOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListAppInstanceBotsOutput");
        formatter.field("app_instance_arn", &self.app_instance_arn);
        formatter.field("app_instance_bots", &self.app_instance_bots);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for ListAppInstanceBotsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAppInstanceBotsOutput {
    /// Creates a new builder-style object to manufacture [`ListAppInstanceBotsOutput`](crate::operation::list_app_instance_bots::ListAppInstanceBotsOutput).
    pub fn builder() -> crate::operation::list_app_instance_bots::builders::ListAppInstanceBotsOutputBuilder {
        crate::operation::list_app_instance_bots::builders::ListAppInstanceBotsOutputBuilder::default()
    }
}

/// A builder for [`ListAppInstanceBotsOutput`](crate::operation::list_app_instance_bots::ListAppInstanceBotsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ListAppInstanceBotsOutputBuilder {
    pub(crate) app_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) app_instance_bots: ::std::option::Option<::std::vec::Vec<crate::types::AppInstanceBotSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAppInstanceBotsOutputBuilder {
    /// <p>The ARN of the AppInstance.</p>
    pub fn app_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the AppInstance.</p>
    pub fn set_app_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_instance_arn = input;
        self
    }
    /// <p>The ARN of the AppInstance.</p>
    pub fn get_app_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_instance_arn
    }
    /// Appends an item to `app_instance_bots`.
    ///
    /// To override the contents of this collection use [`set_app_instance_bots`](Self::set_app_instance_bots).
    ///
    /// <p>The information for each requested <code>AppInstanceBot</code>.</p>
    pub fn app_instance_bots(mut self, input: crate::types::AppInstanceBotSummary) -> Self {
        let mut v = self.app_instance_bots.unwrap_or_default();
        v.push(input);
        self.app_instance_bots = ::std::option::Option::Some(v);
        self
    }
    /// <p>The information for each requested <code>AppInstanceBot</code>.</p>
    pub fn set_app_instance_bots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AppInstanceBotSummary>>) -> Self {
        self.app_instance_bots = input;
        self
    }
    /// <p>The information for each requested <code>AppInstanceBot</code>.</p>
    pub fn get_app_instance_bots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AppInstanceBotSummary>> {
        &self.app_instance_bots
    }
    /// <p>The token passed by previous API calls until all requested bots are returned.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token passed by previous API calls until all requested bots are returned.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token passed by previous API calls until all requested bots are returned.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListAppInstanceBotsOutput`](crate::operation::list_app_instance_bots::ListAppInstanceBotsOutput).
    pub fn build(self) -> crate::operation::list_app_instance_bots::ListAppInstanceBotsOutput {
        crate::operation::list_app_instance_bots::ListAppInstanceBotsOutput {
            app_instance_arn: self.app_instance_arn,
            app_instance_bots: self.app_instance_bots,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for ListAppInstanceBotsOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ListAppInstanceBotsOutputBuilder");
        formatter.field("app_instance_arn", &self.app_instance_arn);
        formatter.field("app_instance_bots", &self.app_instance_bots);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
