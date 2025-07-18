// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about clients using the deprecated resources.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClientStat {
    /// <p>The user agent of the Kubernetes client using the deprecated resource.</p>
    pub user_agent: ::std::option::Option<::std::string::String>,
    /// <p>The number of requests from the Kubernetes client seen over the last 30 days.</p>
    pub number_of_requests_last30_days: i32,
    /// <p>The timestamp of the last request seen from the Kubernetes client.</p>
    pub last_request_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ClientStat {
    /// <p>The user agent of the Kubernetes client using the deprecated resource.</p>
    pub fn user_agent(&self) -> ::std::option::Option<&str> {
        self.user_agent.as_deref()
    }
    /// <p>The number of requests from the Kubernetes client seen over the last 30 days.</p>
    pub fn number_of_requests_last30_days(&self) -> i32 {
        self.number_of_requests_last30_days
    }
    /// <p>The timestamp of the last request seen from the Kubernetes client.</p>
    pub fn last_request_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_request_time.as_ref()
    }
}
impl ClientStat {
    /// Creates a new builder-style object to manufacture [`ClientStat`](crate::types::ClientStat).
    pub fn builder() -> crate::types::builders::ClientStatBuilder {
        crate::types::builders::ClientStatBuilder::default()
    }
}

/// A builder for [`ClientStat`](crate::types::ClientStat).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClientStatBuilder {
    pub(crate) user_agent: ::std::option::Option<::std::string::String>,
    pub(crate) number_of_requests_last30_days: ::std::option::Option<i32>,
    pub(crate) last_request_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ClientStatBuilder {
    /// <p>The user agent of the Kubernetes client using the deprecated resource.</p>
    pub fn user_agent(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_agent = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user agent of the Kubernetes client using the deprecated resource.</p>
    pub fn set_user_agent(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_agent = input;
        self
    }
    /// <p>The user agent of the Kubernetes client using the deprecated resource.</p>
    pub fn get_user_agent(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_agent
    }
    /// <p>The number of requests from the Kubernetes client seen over the last 30 days.</p>
    pub fn number_of_requests_last30_days(mut self, input: i32) -> Self {
        self.number_of_requests_last30_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of requests from the Kubernetes client seen over the last 30 days.</p>
    pub fn set_number_of_requests_last30_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_requests_last30_days = input;
        self
    }
    /// <p>The number of requests from the Kubernetes client seen over the last 30 days.</p>
    pub fn get_number_of_requests_last30_days(&self) -> &::std::option::Option<i32> {
        &self.number_of_requests_last30_days
    }
    /// <p>The timestamp of the last request seen from the Kubernetes client.</p>
    pub fn last_request_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_request_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of the last request seen from the Kubernetes client.</p>
    pub fn set_last_request_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_request_time = input;
        self
    }
    /// <p>The timestamp of the last request seen from the Kubernetes client.</p>
    pub fn get_last_request_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_request_time
    }
    /// Consumes the builder and constructs a [`ClientStat`](crate::types::ClientStat).
    pub fn build(self) -> crate::types::ClientStat {
        crate::types::ClientStat {
            user_agent: self.user_agent,
            number_of_requests_last30_days: self.number_of_requests_last30_days.unwrap_or_default(),
            last_request_time: self.last_request_time,
        }
    }
}
